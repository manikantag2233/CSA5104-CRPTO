# SHA-3 lanes coverage simulation (Python 3)
# See description and assumptions in the message.

import random, math, statistics

def analytic_expected_rounds(rate_lanes=16, total_lanes=25, capacity_lanes=9):
    p = rate_lanes / total_lanes
    k = capacity_lanes
    s = 0.0
    for t in range(0,10000):
        prob = 1.0 - (1.0 - (1.0 - p)**t)**k
        s += prob
        if prob < 1e-14:
            break
    return s, p

def monte_carlo_rounds(trials=20000, rate_lanes=16, total_lanes=25, capacity_lanes=9):
    rate_set = set(range(rate_lanes))  # initial nonzero lanes (choose 0..rate_lanes-1)
    capacity_set = set(range(rate_lanes, total_lanes))
    results = []
    for _ in range(trials):
        visited = set()
        rounds = 0
        nonzero = set(rate_set)
        while True:
            rounds += 1
            perm = list(range(total_lanes))
            random.shuffle(perm)
            mapped = set(perm[i] for i in nonzero)
            visited |= (mapped & capacity_set)
            if visited == capacity_set:
                results.append(rounds)
                break
    return statistics.mean(results), statistics.median(results), min(results), max(results), statistics.pstdev(results)

if __name__ == "__main__":
    analytic_E, p = analytic_expected_rounds()
    mc_mean, mc_median, mc_min, mc_max, mc_std = monte_carlo_rounds(trials=20000)

    print("Model parameters: total_lanes=25, rate_lanes=16, capacity_lanes=9")
    print(f"Single-round hit probability p = {p:.6f} ({int(16)}/{25})\n")

    print("Analytic expected rounds until all capacity lanes hit (E[M]): {:.6f}".format(analytic_E))
    print("Monte-Carlo (20,000 trials): mean = {:.6f}, median = {}, min = {}, max = {}, std = {:.6f}".format(
        mc_mean, mc_median, mc_min, mc_max, mc_std))

    k = 9
    print("\nDistribution P(all capacity lanes hit within t rounds)")
    for t in range(1,8):
        cdf = (1 - (1 - p)**t)**k
        print(f"  t = {t:2d}: P = {cdf:.6f}")

    print(f"\nProbability all done within 3 rounds: {(1 - (1 - p)**3)**k:.6f}")
