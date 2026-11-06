"""Train the LEAP eviction policy: imitation warm start + simulation-in-the-loop CMA-ES.

Policy: decay probability for the minimum-count bucket on a full collision,
    p(P, h, tau) = sigmoid( theta . phi(P, h, tau) ),
    phi = [1, u, u^2, h1, h2, h1*h2, tau, u*h1*h2, u*(1-h1)*(1-h2)],  u = log2(P+1)/11,
    h1/h2 = owner present in window t-1 / t-2, tau = (t-1)/M.
Stage 1 (imitation): from decay-opportunity logs collected under the Pontus rule, fit
    q(phi) = Pr[owner ends up persistent] (logistic regression) and regress theta onto the
    risk-weighted prior  logit p0 = log(1 - q) - log(P + 1).
Stage 2 (policy search): CMA-ES on theta, fitness = mean over memory sizes and seeds of
    AAE(policy)/AAE(Pontus rule) on persistent flows of the TRAINING trace only (January).
Output: theta, the compiled lookup table (T x H x NP), and the optimisation history, in train/out/<POLICY_DIR>/.

Usage (from the repository root, after building train/leap_sim and logging the decay opportunities, see README):
  POLICY_DIR=policy python3 train/learn_policy.py 14 8                                       # Stage 1 + 14 generations
  POLICY_DIR=policy_final python3 train/learn_policy.py 12 8 train/out/policy/leap_policy.json   # restart, 12 more
Arguments: generations, population size, optional warm start (theta of an earlier run).
Environment: TRAIN_KEYS (training key stream, default data/mawi_202601151400.bin), LOG_PREFIX (logs
data/logs/<prefix>_m16.bin and _m32.bin, default jan), TRAIN_MEMS (fitness memory sizes in KB, default 16,32,64).
"""
import json, os, subprocess, sys, time
from multiprocessing import Pool
import numpy as np
import cma
from sklearn.linear_model import LogisticRegression

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEAP = os.path.join(ROOT, "train", "leap_sim")       # functional model (train/leap_sim.cpp)
TRAIN = os.environ.get("TRAIN_KEYS", os.path.join(ROOT, "data", "mawi_202601151400.bin"))   # training trace
LOGP = os.environ.get("LOG_PREFIX", "jan")      # decay-opportunity logs data/logs/<LOGP>_m<mem>.bin
OUT = os.path.join(ROOT, "train", "out", os.environ.get("POLICY_DIR", "policy")); os.makedirs(OUT, exist_ok=True)
M = 1500
T_BINS, H_BINS, NP = 8, 4, 24
MEMS = [int(x) for x in os.environ.get("TRAIN_MEMS", "16,32,64").split(",")]   # fitness memory sizes (KB)
SEEDS = [1, 2]


def phi(u, h, tau):
    h1 = (h & 1).astype(float); h2 = ((h >> 1) & 1).astype(float)
    return np.stack([np.ones_like(u), u, u * u, h1, h2, h1 * h2, tau, u * h1 * h2, u * (1 - h1) * (1 - h2)], 1)


def table_from_theta(theta):
    tb, hh, pb = np.meshgrid(np.arange(T_BINS), np.arange(H_BINS), np.arange(NP), indexing="ij")
    # representative count of each hardware bin (pbin = 2*msb(P) + next bit)
    k, bb = pb // 2, pb % 2
    Prep = np.where(k == 0, 1.0, np.ldexp(1.0 + (bb + 0.5) / 2.0, k))
    u = np.log2(Prep + 1) / 11; tau = (tb + 0.5) / T_BINS
    z = phi(u.ravel(), hh.ravel(), tau.ravel()) @ theta
    return 1 / (1 + np.exp(-z))                       # flat, [t][h][p] order


def write_table(theta, path):
    p = table_from_theta(theta)
    with open(path, "w") as f:
        f.write(f"{T_BINS} {H_BINS} {NP}\n" + " ".join(f"{x:.8g}" for x in p) + "\n")


def run_eval(args):
    trace, mem, kind, seed, table = args
    out = subprocess.run([LEAP, "eval", trace, str(M), str(mem), str(seed), table], capture_output=True, text=True, check=True).stdout
    return json.loads(out.strip().splitlines()[-1])


def baseline_aae(pool):
    jobs = [(TRAIN, m, "leap", s, "-") for m in MEMS for s in SEEDS]
    res = pool.map(run_eval, jobs)
    return {(r["mem_KB"], r["seed"]): r["AAE"] for r in res}


def fitness(theta, pool, base, tag):
    path = os.path.join(OUT, f"cand_{tag}.txt"); write_table(theta, path)
    res = pool.map(run_eval, [(TRAIN, m, "leap", s, path) for m in MEMS for s in SEEDS])
    rel = [r["AAE"] / base[(r["mem_KB"], r["seed"])] for r in res]
    return float(np.mean(rel)), {f"{r['mem_KB']:.0f}KB_s{r['seed']}": r["AAE"] for r in res}


def imitation():
    X, y = [], []
    for mem in [16, 32]:
        a = np.fromfile(os.path.join(ROOT, "data", "logs", f"{LOGP}_m{mem}.bin"), dtype=np.uint16).reshape(-1, 4).astype(np.int64)
        idx = np.random.default_rng(0).choice(len(a), size=min(len(a), 1_500_000), replace=False); a = a[idx]
        P, h, lab = a[:, 0], a[:, 1], a[:, 3]
        # the log was collected with the Pontus rule (no table): time bin is not logged -> use uniform tau
        tau = np.random.default_rng(1).random(len(P))
        X.append(phi(np.log2(P + 1) / 11, h, tau)); y.append(lab)
    X, y = np.vstack(X), np.concatenate(y)
    clf = LogisticRegression(C=1.0, max_iter=500).fit(X[:, 1:], y)
    q = clf.predict_proba(X[:, 1:])[:, 1]
    P = 2 ** (X[:, 1] * 11) - 1
    z0 = np.log(np.clip(1 - q, 1e-4, 1)) - np.log(P + 1)
    theta0, *_ = np.linalg.lstsq(X, z0, rcond=None)
    print(f"imitation: {len(y)} decay opportunities, {y.mean():.3%} on persistent owners, "
          f"classifier acc {(clf.predict(X[:, 1:]) == y).mean():.3f}")
    return theta0, clf


def main(gens=14, popsize=8, init=None):
    t0 = time.time()
    pool = Pool(4)
    base = baseline_aae(pool)
    print("Pontus-rule AAE on Jan:", {f"{k[0]:.0f}KB_s{k[1]}": round(v, 2) for k, v in base.items()}, flush=True)
    theta0, _ = imitation()
    write_table(theta0, os.path.join(OUT, "imitation_table.txt"))
    fi, di = fitness(theta0, pool, base, "imit")
    print(f"imitation-only policy: rel {fi:.3f} {di}", flush=True)
    json.dump({"rel": fi, "detail": di, "theta": theta0.tolist()}, open(os.path.join(OUT, "imitation_eval.json"), "w"))
    if init is not None:                       # warm start from a previous search (same features)
        theta0 = np.array(json.load(open(init))["theta"])
    f0, d0 = fitness(theta0, pool, base, "init")
    print(f"imitation policy: rel {f0:.3f} {d0}", flush=True)
    hist = [{"gen": 0, "best_rel": f0, "detail": d0, "theta": theta0.tolist(), "time": time.time() - t0}]
    es = cma.CMAEvolutionStrategy(theta0, 0.6, {"popsize": popsize, "seed": 7, "verbose": -9})
    best = (f0, theta0, d0)
    for g in range(1, gens + 1):
        sols = es.ask()
        fits = []
        for i, s in enumerate(sols):
            f, d = fitness(np.array(s), pool, base, f"g{g}_{i}"); fits.append(f)
            if f < best[0]: best = (f, np.array(s), d)
        es.tell(sols, fits)
        hist.append({"gen": g, "best_rel": best[0], "gen_mean": float(np.mean(fits)), "gen_min": float(np.min(fits)),
                     "detail": best[2], "theta": best[1].tolist(), "time": time.time() - t0})
        print(f"gen {g}: min {np.min(fits):.3f} mean {np.mean(fits):.3f} best-so-far {best[0]:.3f} [{time.time() - t0:.0f}s]", flush=True)
        json.dump(hist, open(os.path.join(OUT, "history.json"), "w"), indent=1)
    write_table(best[1], os.path.join(OUT, "leap_table.txt"))
    json.dump({"theta": best[1].tolist(), "theta_imitation": theta0.tolist(), "rel": best[0], "detail": best[2]},
              open(os.path.join(OUT, "leap_policy.json"), "w"), indent=1)
    for f in os.listdir(OUT):
        if f.startswith("cand_"): os.remove(os.path.join(OUT, f))
    print("done", best[0])


if __name__ == "__main__":
    a = sys.argv[1:]
    main(int(a[0]) if a else 14, int(a[1]) if len(a) > 1 else 8, a[2] if len(a) > 2 else None)
