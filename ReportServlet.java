package com.corp.reports;

import java.io.ObjectInputStream;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {

    // VULN 1: Insecure Deserialization — untrusted request bytes are passed to
    // ObjectInputStream.readObject(), enabling gadget-chain RCE.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ObjectInputStream in = new ObjectInputStream(req.getInputStream());
        Object filter = in.readObject(); // RCE via crafted serialized payload
        resp.getWriter().println("restored: " + filter);
    }

    // VULN 2: Code Injection — a user-supplied "formula" is evaluated by the
    // Nashorn script engine, giving arbitrary Java/JS execution (RCE).
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String formula = req.getParameter("formula"); // ?formula=java.lang.Runtime.getRuntime().exec('id')
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        Object result = engine.eval(formula);
        resp.getWriter().println("result: " + result);
    }

    // VULN 3: Improper Certificate Validation — a TrustManager that accepts any
    // certificate is installed globally, disabling TLS authentication and
    // exposing every outbound HTTPS call to MITM.
    static {
        try {
            TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
