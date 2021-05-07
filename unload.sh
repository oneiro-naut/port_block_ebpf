ifaces=( $(ip addr list | awk -F': ' '/^[0-9]/ {print $2}') )
echo ${ifaces[@]}
#ip link set dev em1 xdp obj xdp-example.o
for i in "${ifaces[@]}"
do
   ip link set dev $i xdp off
done