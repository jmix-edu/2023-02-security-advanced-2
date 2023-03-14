package com.company.samplesales.app;


import io.jmix.core.UnconstrainedDataManager;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/public/product")
public class ProductPublicService {

    private UnconstrainedDataManager dataManager;

    public ProductPublicService(UnconstrainedDataManager dataManager) {
        this.dataManager = dataManager;
    }

    @GetMapping("/list")
    public ResponseEntity<List<String>> list() {
        List<String> names = dataManager.loadValues("select p.name from sales_Product p " +
                        "where p.special IS NULL or p.special = false " +
                        "order by p.name")
                .property("name")
                .list()
                .stream().map(row -> (String) row.getValue("name"))
                .collect(Collectors.toList());
        return new ResponseEntity<>(names, HttpStatus.OK);
    }
}
