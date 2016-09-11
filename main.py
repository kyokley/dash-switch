from scapy.all import sniff, DHCP, BOOTP
from ouimeaux.environment import Environment
from ouimeaux.utils import matcher

GATORADE = '74:75:48:41:3c:1c'
TIDE = '00:bb:3a:c3:52:8e'

DISCOVER_MESSAGE = ('message-type', 1)

SWITCH_NAME = 'Bedroom'
matches = matcher(SWITCH_NAME)

def main():
    sniff(prn=toggle_switch, filter="port 67 and ether src %s" % TIDE, store=0)

def get_switch():
    env = Environment()

    try:
        env.start()
    except:
        pass

    env.discover(5)
    found = None
    for switch in env.list_switches():
        if matches(switch):
            found = env.get_switch(switch)
            break
    else:
        raise Exception('Switch not found!')

    return found

def toggle_switch(pkt):
    if (DHCP in pkt and
            BOOTP in pkt and
            pkt[BOOTP].op == 1 and
            DISCOVER_MESSAGE in pkt[DHCP].options):
        switch = get_switch()
        if switch and switch.get_state():
            switch.off()
        else:
            switch.on()

if __name__ == '__main__':
    main()
