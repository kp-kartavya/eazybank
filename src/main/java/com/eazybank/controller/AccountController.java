package com.eazybank.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
    @GetMapping("/myAccounts")
    public String myAccounts() {
        return "Here are acoount details from the DB";
    }
}
