import os
import sys

import matplotlib.pyplot as plt
import pandas as pd


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} file1 [...file2]")
        exit(255)
    files = sys.argv[1:]
    for f in files:
        data = pd.read_csv(f)
        # plot each file
        print(f)
        print(data[data['timing'] > 1000].to_numpy())
        ax = data.plot(title=f"Access Timings ({f})",
                       xticks=data[data['timing'] > 1000].index.array)
        ax.set_xlabel("Experiment No.")
        ax.set_ylabel("Timing in Cycles")

        print("Mean access time for non peak values {}".format(data[ data['timing'] < 800].mean()[0]))
        # build data frame that contains the indices from 'frame', where the
        # timing was over the specified threshold,  as values

        indicesHighTiming = pd.DataFrame(data[ data['timing'] > 1000 ].index.array)
        print("Got {} timing peaks".format(indicesHighTiming.count()[0]))
        diffBetweenHighTimings = indicesHighTiming.diff()
        print("Mean distance between timing peaks is {} with std. deviation of {}".format(round(diffBetweenHighTimings.mean()[0], ndigits=2),diffBetweenHighTimings.std()[0]))

        plt.show()


if __name__ == '__main__':
    main()