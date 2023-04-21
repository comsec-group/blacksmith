import os
import sys

import matplotlib.pyplot as plt
import pandas as pd


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} file1 [...file2]")
        exit(255)
    files = sys.argv[1:]
    min_peak = 1000  # timing considered to be high latency
    max_peak = 5000  # upper bound to filter outliers
    for f in files:
        # plot each file
        data = pd.read_csv(f)
        print(f)
        data = data[data['timing'] < max_peak]  # filter outliers
        print(data[data['timing'] > min_peak].to_numpy())
        ax = data.plot(title=f"Access Timings ({f})",
                       xticks=data[data['timing'] > min_peak].index.array)
        ax.set_xlabel("Experiment No.")
        ax.set_ylabel("Timing in Cycles")

        print("Mean access time for non peak values {}".format(data[ data['timing'] < min_peak].mean()[0]))
        # build data frame that contains the indices from 'frame', where the
        # timing was over the specified threshold,  as values

        indicesHighTiming = pd.DataFrame(data[data['timing'] > min_peak].index.array)
        print("Got {} timing peaks".format(indicesHighTiming.count()[0]))
        diffBetweenHighTimings = indicesHighTiming.diff()
        print("Mean distance between timing peaks is {} with std. deviation of {}".format(round(diffBetweenHighTimings.mean()[0], ndigits=2),diffBetweenHighTimings.std()[0]))
        print(f"You might want to use acts_per_trefi={int(diffBetweenHighTimings.mean()[0]*2)}")

        plt.show()


if __name__ == '__main__':
    main()