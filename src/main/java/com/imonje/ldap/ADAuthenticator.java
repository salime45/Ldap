package com.imonje.ldap;

import java.util.HashMap;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 * Clase que se valida contra active directory
 *
 * @author imonje
 */
public class ADAuthenticator {

    private final String domain;
    private final String ldapHost;
    private final String searchBase;

    public ADAuthenticator(String domain, String ip, String puerto) {

        this.domain = domain;
        this.ldapHost = "ldap://" + ip + ":" + puerto;

        String[] aux = domain.split("\\.");
        String sb = "";

        for (int i = 0; i < aux.length; i++) {
            sb += "dc=" + aux[i] + ",";
        }
        this.searchBase = sb.substring(0, sb.length() - 1);
    }

    public boolean isMemberOf(String user, String pass, String group) {
        
        String returnedAtts[] = {"memberOf"};
        String searchFilter = "(&(objectClass=user)(sAMAccountName=" + user + "))";

        //Create the search controls
        SearchControls searchCtls = new SearchControls();
        searchCtls.setReturningAttributes(returnedAtts);

        //Specify the search scope
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapHost);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, user + "@" + domain);
        env.put(Context.SECURITY_CREDENTIALS, pass);

        LdapContext ctxGC = null;

        try {
            ctxGC = new InitialLdapContext(env, null);
            //Search objects in GC using filters
            NamingEnumeration answer = ctxGC.search(searchBase, searchFilter, searchCtls);
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attrs = sr.getAttributes();

                if (attrs != null) {
                    System.out.println("---> " + attrs.get("memberOf").toString());
//                    System.out.println("CN="+group+",");
//                  System.out.println(attrs.get("memberOf").toString().contains("CN="+group+","));
                    return attrs.get("memberOf").toString().contains("CN="+group+",");
                        
                }
                return false;
            }
        } catch (NamingException ex) {
            System.err.println(ex.getMessage());
        }

        return false;
    }
    
    public HashMap<String, String> allUser(String user, String pass) {
        
        String returnedAtts[] = {"sn", "givenName"};
        String searchFilter = "(&(objectClass=user)(sAMAccountName=" + user + "))";

        //Create the search controls
        SearchControls searchCtls = new SearchControls();
        searchCtls.setReturningAttributes(null);

        //Specify the search scope
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapHost);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, user + "@" + domain);
        env.put(Context.SECURITY_CREDENTIALS, pass);

        LdapContext ctxGC = null;

        try {
            ctxGC = new InitialLdapContext(env, null);
            //Search objects in GC using filters
            NamingEnumeration answer = ctxGC.search(searchBase, searchFilter, searchCtls);
            while (answer.hasMoreElements()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attrs = sr.getAttributes();
                HashMap<String, String > amap = null;
                if (attrs != null) {
                    amap = new HashMap<>();
                    NamingEnumeration ne = attrs.getAll();
                    while (ne.hasMore()) {
                        Attribute attr = (Attribute) ne.next();
                        amap.put(attr.getID(), attr.get().toString());
                    }
                    ne.close();
                }
                return amap;
            }
        } catch (NamingException ex) {
            System.err.println(ex.getMessage());
        }

        return null;
    }
}
