package com.corp.catalog;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class ProductController {

    // VULN 1: SpEL Injection — a user-supplied string is parsed and evaluated as
    // a Spring Expression, giving arbitrary Java execution (RCE).
    @GetMapping("/filter")
    public String filter(@RequestParam String q) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(q); // ?q=T(java.lang.Runtime).getRuntime().exec("id")
        return String.valueOf(exp.getValue());
    }

    // VULN 2: XML Injection — user values are concatenated into an XML document
    // without encoding, so input can inject or alter elements consumed
    // downstream as trusted XML.
    @PostMapping("/order")
    public String order(@RequestParam String item, @RequestParam String qty) {
        String xml = "<order><item>" + item + "</item><qty>" + qty + "</qty></order>";
        return xml;
    }

    // VULN 3: Insecure Deserialization via XMLDecoder — decodes attacker-supplied
    // XML into live objects, a well-known Java RCE sink.
    @PostMapping("/import")
    public String importData(@RequestBody byte[] body) {
        XMLDecoder dec = new XMLDecoder(new ByteArrayInputStream(body));
        Object o = dec.readObject(); // RCE
        return "imported: " + o;
    }
}
