package com.eazybank.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BalanceController {
    @GetMapping("/myBalances")
    public String myBalances() {
        return "Here are acoount balance details from the DB";
    }
}
