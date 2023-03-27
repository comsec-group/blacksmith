import matplotlib.pyplot as plt
import pandas as pd


def main():
    files = ['access-timings.csv']

    no_conflict_threshold = 300
    conflict_threshold = 300

    for f in files:
        data = pd.read_csv(f)
        print(f)

        print("Mean access time for non peak values {}".format(data[data['timing'] < no_conflict_threshold].mean()[0]))
        # build data frame that contains the indices from 'frame', where the
        # timing was over the specified threshold,  as values

        highTiming = data[data['timing'] > conflict_threshold]
        indicesHighTiming = pd.DataFrame(highTiming.index.array)
        print("Got {} timing peaks".format(indicesHighTiming.count()[0]))
        diffBetweenHighTimings = highTiming.diff()
        print("Mean access time for peak values {}. Difference between timing peaks is {} with std {}".format(
            highTiming.mean()[0],
            diffBetweenHighTimings.mean()[0],
            diffBetweenHighTimings.std()[0]))

        plt.show()


if __name__ == '__main__':
    main()