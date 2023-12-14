from singman.process import singman_init, singman_menu, singman_parse

if __name__ == "__main__":
    singman_init("launch")
    server_conf, client_conf = singman_parse(
        "launch/data/config.json", "launch/data/client_config.json"
    )
    print("input node name:")
    node_name = input("> ")
    while True:
        singman_menu(server_conf, client_conf, node_name=node_name)
