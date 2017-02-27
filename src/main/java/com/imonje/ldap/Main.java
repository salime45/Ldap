package com.imonje.ldap;

/**
 *
 * @author imonje
 */
public class Main {

    public static void main(String[] args) {

        if (args.length < 6) {
            System.err.println("Parametros incorrectos. Domain Ip Puerto Usuario Contraseña Grupo ");
        } else {
            String domain = args[0];
            String ip = args[1];
            String port = args[2];
            String usuario = args[3];
            String pass = args[4];
            String grupo = args[5];

            ADAuthenticator ad = new ADAuthenticator(domain, ip, port);

            if (ad.isMemberOf(usuario, pass, grupo)) {
                System.out.println("1");
            } else {
                System.out.println("0");

            }
        }
    }

}
