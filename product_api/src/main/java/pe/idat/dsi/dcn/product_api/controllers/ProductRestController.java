package pe.idat.dsi.dcn.product_api.controllers;

import java.net.URI;
import java.util.List;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import pe.idat.dsi.dcn.product_api.dtos.BasePageableDto;
import pe.idat.dsi.dcn.product_api.dtos.GetAllProductPageableResponse;
import pe.idat.dsi.dcn.product_api.dtos.GetAllProductResponse;
import pe.idat.dsi.dcn.product_api.dtos.GetProductByIdResponse;
import pe.idat.dsi.dcn.product_api.dtos.UpdateCodigoProductRequest;
import pe.idat.dsi.dcn.product_api.models.Product;
import pe.idat.dsi.dcn.product_api.services.ProductService;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/v1/products")
public class ProductRestController {
    private ProductService productService;

    public ProductRestController(ProductService service){
        this.productService = service;
    }

    @GetMapping
    public ResponseEntity<List<GetAllProductResponse>> getAll(){
        return ResponseEntity.status(HttpStatus.OK).body(productService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<GetProductByIdResponse> getById(@PathVariable Long id) {
        var response = productService.getById(id);
         
         return response != null ? 
             ResponseEntity.ok(response):
             ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
     }

    @GetMapping("/paging")
    public  ResponseEntity<BasePageableDto<GetAllProductPageableResponse>> getAllPageable(
        @RequestParam(defaultValue = "0") int pageNumber,
        @RequestParam(defaultValue = "5") int pageSize, 
        @RequestParam(defaultValue = "id") String sortColumn,
        @RequestParam(defaultValue = "asc") String sortOrder, 
        @RequestParam(defaultValue = "") String nombre, 
        @RequestParam(defaultValue = "") String codigo) {
        return ResponseEntity.ok(productService.getAllPageable(pageNumber, pageSize, sortColumn, sortOrder, nombre, codigo));
    }

    @PostMapping
    public ResponseEntity<Product> create(@RequestBody Product entity){
        try {
            var response = productService.create(entity);
            return ResponseEntity.created(URI.create("/api/v1/products/"+response.getId())).body(entity);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<Product> update(@PathVariable Long id, @RequestBody Product entity) {
        
        var response = productService.update(id, entity);

        if(response == null){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
        
        return ResponseEntity.ok(entity);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id){
        boolean hasRemoved = productService.delete(id);
        return hasRemoved ? 
            ResponseEntity.noContent().build() : 
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    }

    @PatchMapping()
    public ResponseEntity<Product> delete(@RequestBody UpdateCodigoProductRequest filter) {
        try {
            var product = productService.updateCodigo(filter.getId(), filter.getCodigo());
            return product == null ? 
                ResponseEntity.notFound().build() : 
                ResponseEntity.ok(product);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}
