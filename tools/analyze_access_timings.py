#!/usr/bin/env python3

import sys

import matplotlib.pyplot as plt
import pandas as pd


def main():
    if len(sys.argv) < 4:
        import os
        print(f"Usage: {os.path.basename(sys.argv[0])} no-conflict-threshold conflict-threshold file1 [...file2]")
        print(f"Example: {os.path.basename(sys.argv[0])} 250 300 access-timings.csv")
        print("\tAnalyze access times from a CSV file, grouping access times in timings less than "
              "no-conflict-threshold and greater than conflict-threshold.")
        exit(255)

    files = sys.argv[3:]

    no_conflict_threshold = int(sys.argv[1])
    conflict_threshold = int(sys.argv[2])

    assert conflict_threshold >= no_conflict_threshold, "conflict threshold must be greater than or equal to " \
                                                        "no-conflict-threshold "

    for f in files:
        data = pd.read_csv(f)
        lowTiming = data[data['timing'] < no_conflict_threshold]
        print(f"len(<no-conflict-threshold): {lowTiming.count()[0]}")
        print(f"mean(<no-conflict-threshold): {lowTiming.mean()[0]}")
        # build data frame that contains the indices from 'frame', where the
        # timing was over the specified threshold,  as values

        highTiming = data[data['timing'] > conflict_threshold]
        indicesHighTiming = pd.DataFrame(highTiming.index.array)
        diffBetweenHighTimings = highTiming.diff()
        print(f"len(>conflict-threshold): {indicesHighTiming.count()[0]}")
        print(f"mean(>conflict-threshold): {highTiming.mean()[0]}")
        print(f"mean(diff(>conflict-threshold)): {diffBetweenHighTimings.mean()[0]}")
        print(f"std(mean(diff(>conflict-threshold))): {diffBetweenHighTimings.std()[0]}")

        plt.show()


if __name__ == '__main__':
    main()