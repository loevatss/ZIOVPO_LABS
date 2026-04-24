package ru.mfa.antivirus.dto;

import ru.mfa.antivirus.model.Product;

public class ProductCatalogResponse {
    private Long id;
    private String name;
    private boolean blocked;

    public static ProductCatalogResponse from(Product product) {
        ProductCatalogResponse response = new ProductCatalogResponse();
        response.setId(product.getId());
        response.setName(product.getName());
        response.setBlocked(product.isBlocked());
        return response;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }
}
