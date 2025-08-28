Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"

  common_bootstrap = <<-SHELL
    set -euxo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends build-essential make iproute2 ca-certificates curl gpg wireshark
  SHELL

  nodes = [
    {name: "vm-sat",   target: "sat",   ip: "192.168.56.11", emu: true,  lan: nil,       desktop: true },
    {name: "vm-gw",    target: "gw",    ip: "192.168.56.12", emu: true,  lan: "lan-gw",  desktop: true },
    {name: "vm-st",    target: "st",    ip: "192.168.56.13", emu: true,  lan: "lan-st",  desktop: true },
    {name: "vm-ws-gw", target: "ws_gw", ip: "192.168.56.14", emu: nil,   lan: "lan-gw",  desktop: true },
    {name: "vm-ws-st", target: "ws_st", ip: "192.168.56.15", emu: nil,   lan: "lan-st",  desktop: true },
  ]

  nodes.each do |n|
    config.vm.define n[:name] do |node|
      node.vm.hostname = n[:name]

      node.vm.network "private_network",
        ip: n[:ip],
        virtualbox__adapter: 2

      if n[:emu]
        node.vm.network "private_network",
          virtualbox__intnet: "emu-net",
          auto_config: false,
          virtualbox__adapter: 4
      end

      if n[:lan]
        node.vm.network "private_network",
          virtualbox__intnet: n[:lan],
          auto_config: false,
          virtualbox__adapter: 5
      end

      node.vm.provider :virtualbox do |vb|
        vb.name   = n[:name]
        vb.cpus   = 2
        vb.memory = n[:desktop] ? 4096 : 2048  # more RAM if desktop
        vb.gui    = n[:desktop] ? true : false

        vb.customize ["modifyvm", :id, "--graphicscontroller", "vmsvga"]
        vb.customize ["modifyvm", :id, "--vram", "128"]
      end

      node.vm.provision "shell", inline: common_bootstrap

      if n[:desktop]
        node.vm.provision "shell", privileged: true, inline: <<-SHELL
          set -euxo pipefail
          export DEBIAN_FRONTEND=noninteractive
          apt-get update
          # Desktop environment (minimal), display manager, X, and VBox guest X11
          apt-get install -y --no-install-recommends ubuntu-desktop-minimal gdm3 xorg virtualbox-guest-x11
          # Boot to graphical target
          systemctl set-default graphical.target
        SHELL
      end

node.vm.provision "shell", privileged: true, inline: <<-SHELL
  set -euxo pipefail
  mkdir -p /etc/apt/keyrings
  curl -sS https://raw.githubusercontent.com/CNES/net4sat-packages/master/gpg/net4sat.gpg.key \
    | gpg --dearmor > /etc/apt/keyrings/net4sat.gpg
  cat << EOF > /etc/apt/sources.list.d/github.net4sat.sources
Types: deb
URIs: https://raw.githubusercontent.com/CNES/net4sat-packages/master/jammy/
Suites: jammy
Components: stable
Signed-By: /etc/apt/keyrings/net4sat.gpg
EOF
  apt-get update
  apt-get install -y opensand 
SHELL

      node.vm.provision "shell", privileged: true, inline: <<-SHELL
        cd /vagrant/gw_xml/#{n[:target]}
        echo "Running make in $(pwd) as root"
        make
      SHELL
    end
  end
end
