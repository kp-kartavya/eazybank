package com.eazybank.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactsController {
    @GetMapping("/myContacts")
    public String myContacts() {
        return "Here are contact details from the DB";
    }
}
