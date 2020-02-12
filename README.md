# Cheetah: P4 code

We implemented Cheetah in P4 on the Tofino. Due to NDA restrictions, we only provide a simplified implementation in P4_16 for both the stateless and stateful implementations. The stateless implementation is fixing the cookie.

## Running the code

We wrote the code on top of the VM provided by ETH Zurich for P4 emulation [link](https://github.com/nsg-ethz/p4-learning). Refer to their tutorial to set up the environment and run the code. 

However, here is a short list of instructions for Ubuntu 18.04, please refer to the full tutorial if you encounter any problem in these steps:
 * `sudo apt install virtualbox vagrant`
 * `git clone https://github.com/nsg-ethz/p4-learning.git`
 * `cd p4-learning/vm/`
 * Share this repository to /vagrant/cheetah-p4/ by adding the following line before the last *end* of the file : `config.vm.synced_folder '/home/tom/workspace/cheetah-p4/', '/vagrant/cheetah-p4'`, changing the first path to match the place where you checked out this repository.
 * We suggest also removing `vb.gui = true` if you're connecting to a remote server.
 * `vagrant up`
 * Then connect to the vagrant machine with `vagrant ssh`

## Limitations

We currently assume all packets have the same TCP options (i.e., [`NOP`,`NOP`,`TIMESTAMP`]). We are looking for an implemention of a parser for TCP options. 

## Network topology

We assume there is a single VIP with IP=`10.0.0.254`, a single client at `10.0.0.1` and two servers at `10.0.0.2` (`server_id=0`) and `10.0.0.3` (`server_id=1`), respectively. We implemented a weighted LB with 6 buckets. The first four buckets are assigned to `10.0.0.2` and the last two to `10.0.0.3`.

## Stateless Cheetah

The main P4 code can be found in `stateless-cheetah.p4`. The Cheetah load balancer inserts the computed cookie when receiving a packet from the server. The LB extracts the cookie for every non-SYN packet and computes the server id to which a packet will be forwarded.

To test the system, one has to launch the environment:

```bash
cd /vagrant/cheetah-p4/
sudo p4run --conf=p4app-stateless.json
```

Open multiple windows, one per client/server, one per link, and one for the switch. We suggest using tmux, available on the machine to do so. On the terminals for the links, monitor the traffic with tcpdump:

`sudo tcpdump -xxx -i s1-eth1`

`sudo tcpdump -xxx -i s1-eth2`

`sudo tcpdump -xxx -i s1-eth3`

On the switch, access the CLI:

`simple_switch_CLI`

On the servers, run:

`mx h2`

`python receive.py`

and

`mx h3`

`python receive.py`

and on the client:

`mx h1`

`sudo arp -s 10.0.0.254 00:50:ba:85:85:ca`, followed by

`python send_syn_port_10.py 10.0.0.254 hey`

This will generate a message that will be send to `10.0.0.2`. The fifth time a SYN is generate, the packet will be sent to `10.0.0.3`i (because the weighted round robin is set to a 4/2 ratio).

Generate now a SYN-ACK from `10.0.0.2`:

`mx h2` 

`python send-syn-ack.py 10.0.0.1 hey`

You can check on the tcpdump that a cookie `23fc` is being attached to the packet in the LSB of the timestamp.

One can now generate a non-syn packet from `10.0.0.1`:

`mx h1`

`python send_non_syn_port_10.py 10.0.0.254 hey`. This packet is pre-configured with a TCP timestamp where the 16-LSB of the TSecr are `23fc`. By hashing the header of the packet with `23fc`, one obtains `0`, which is the server_id of `10.0.0.2`.


## Stateful Cheetah

The main P4 code can be found in `stateful-cheetah.p4`. The Cheetah load balancer has two ConnTable. The LB inserts the cookie when receiving a SYN packet. 

To test the system, one has to launch the environment:

`sudo p4run --conf=p4app-stateful.json`

Open multiple windows, one per client/server, one per link, and one for the switch. On the terminals for the links, monitor the traffic with tcpdump:

`sudo tcpdump -xxx -i s1-eth1`

`sudo tcpdump -xxx -i s1-eth2`

`sudo tcpdump -xxx -i s1-eth3`

On the switch, access the CLI:

`simple_switch_CLI`

On the servers, run:

`mx h2`

`python receive.py`

and

`mx h3`

`python receive.py`

and on the client:

`mx h1`

`sudo arp -s 10.0.0.254 00:50:ba:85:85:ca`, followed by

`python send-syn-port-10.py 10.0.0.254 hey`

This will generate a message that will be send to `10.0.0.2`. Generate four such messages and then send two packets with  source port `11`:

`python send-syn-port-11.py 10.0.0.254 hey`

`python send-syn-port-11.py 10.0.0.254 hey`

These packets will be routed to `10.0.0.3`.

The main insight here is that packets with port `10` have a hash that maps to the first ConnTable while packets with port `11` have a hash that maps to the second ConnTable.

Generate now a SYN-ACK from `10.0.0.2`:

`mx h2` 

`python send-syn-ack.py 10.0.0.1 hey`

The packet will be forwarded unaltered. 

One can now generate a non-syn packet from `10.0.0.1` on port `10` which should go to `10.0.0.2`:

`mx h1`

`python send_non_syn_port_10.py 10.0.0.254 hey`. This packet is pre-configured with a TCP timestamp where the 16-LSB of the TSecr are `0000`. 

When sending a packet with the same timestamp but from port `11`:

`python send_non_syn_port_11.py 10.0.0.254 hey`

the packet will be routed to `10.0.0.3`, using the second ConnTable. 

You can use the `simple_switch_CLI` to track the status of the registers.
