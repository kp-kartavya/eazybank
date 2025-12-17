package com.eazybank.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoticeController {
    @GetMapping("/myNotices")
    public String myNotices() {
        return "Here are notices from the DB";
    }
}
