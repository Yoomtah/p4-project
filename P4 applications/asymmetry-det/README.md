# Detecting Asymmetric flows from attacks over 1 second time frames
A P4 program to recognise and store the direction of flows. e.g. ingress port x and egress port y vs ingress port y and egress port x
Computes the ratio of those values and stores it every sec, resetting every sec (adds one to both values before ratio calc)

Uses hping to simulate a DOS attack

Python script to read the register values and plot attack rate vs asymmetry (gets attack rate from hping commands)
