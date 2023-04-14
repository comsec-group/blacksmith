#!/usr/bin/env python3

import sys

import matplotlib.pyplot as plt
import pandas as pd


def main():
    if len(sys.argv) < 2:
        import os
        print(f"Usage: {os.path.basename(sys.argv[0])} file1 [...file2]")
        print(f"Example: {os.path.basename(sys.argv[0])} access-timings.csv")
        print("\tVisualize access times from a CSV file")
        exit(255)

    files = sys.argv[1:]

    #plot each file
    print("Plotting ", files)
    for f in files:
        data = pd.read_csv(f)
        num_bins = 200
        fig, ax = plt.subplots()
        ax.set_title(f'Access Times ({f})')
        ax.hist(data.to_numpy(), num_bins, density=False)
        ax.set_xlabel('Binned access times')
        ax.set_ylabel('Count')

        plt.show()


if __name__ == '__main__':
    main()
