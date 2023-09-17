## Sing-box Based Reality and Hysteria Installer

### Using Sing-box Wireguard

* Install Warp (Option)

  ```shell
  wget -N https://gitlab.com/fscarmen/warp/-/raw/main/warp-go.sh && bash warp-go.sh n && warp-go e
  # uninstall after install sing-box (option)
  # warp-go u
  ```
  
* Install Sing-box

  ```shell
  mkdir sing-box && cd sing-box
  wget -N https://raw.githubusercontent.com/jungheil/sing-box-installer/main/install.sh && bash install.sh
  ```
  
### Using Warp

* Install Warp (Option)

  ```shell
  wget -N https://gitlab.com/fscarmen/warp/-/raw/main/warp-go.sh && bash warp-go.sh n
  ```

* Install Sing-box

  ```shell
  mkdir sing-box && cd sing-box
  wget -N https://raw.githubusercontent.com/jungheil/sing-box-installer/main/install.sh && bash install.sh --outbound warp_interface
  ```