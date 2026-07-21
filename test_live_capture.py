from nfstream import NFStreamer


def main():

    print("Starting capture...")

    streamer = NFStreamer(
        source=r"\Device\NPF_{D9958CBF-CC13-4A14-8A79-D9F116E4DFCD}",
        statistical_analysis=True,
        idle_timeout=5
    )

    count = 0

    for flow in streamer:

        print(flow.src_ip, "->", flow.dst_ip)

        count += 1

        if count == 5:
            break

    print("Finished")


if __name__ == "__main__":
    main()