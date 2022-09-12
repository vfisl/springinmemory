package com.example.controllers;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProductController {

	@GetMapping("/")
	public String welcome() {
		return "Welcome to Online store";
	}

	@GetMapping("/products")
	public List<String> show() {
		return Arrays.asList("laptop", "mobile");
	}

	@GetMapping("/admin/add-product")
	public String add() {
		return "product added";
	}

	@GetMapping("/admin/delete-product")
	public String delete() {
		return "product deleted";
	}

	@GetMapping("/products/{type}")
	public List<String> showByType(@PathVariable("type") String type) {
		if (type.equalsIgnoreCase("sports"))
			return Arrays.asList("Bat", "Ball");
		else
			return Arrays.asList("laptop", "mobile");
	}
}
