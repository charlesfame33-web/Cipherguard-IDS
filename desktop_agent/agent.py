from capture import capture_live
from sender import send_flows

INTERFACE = "Ethernet 5"


def start():

    print("=" * 60)
    print("🛡️ CipherGuard Desktop Agent Started")
    print("=" * 60)

    for flows in capture_live(INTERFACE):

        if flows.empty:
            continue

        print(f"Extracted {len(flows)} flows...")

        result = send_flows(flows)

        if result:
            print("Prediction Result:")
            print(result)


if __name__ == "__main__":
    start()