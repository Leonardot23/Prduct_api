package pe.idat.dsi.dcn.product_api.services;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;

import pe.idat.dsi.dcn.product_api.dtos.BasePageableDto;
import pe.idat.dsi.dcn.product_api.dtos.GetAllProductPageableResponse;
import pe.idat.dsi.dcn.product_api.dtos.GetAllProductResponse;
import pe.idat.dsi.dcn.product_api.dtos.GetProductByIdResponse;
import pe.idat.dsi.dcn.product_api.models.Product;
import pe.idat.dsi.dcn.product_api.repositories.ProductRepository;

@Service
public class ProductService {

    private ProductRepository productRepository;

    public ProductService(ProductRepository productRepository){
        this.productRepository = productRepository;
    }

    public Product create(Product product){
        var result = productRepository.saveAndFlush(product);
        return result;
    }

    public Product update(Long id, Product entity){
        var response = productRepository.findById(id)
            .orElse(null);
        if(response == null) return null;

        response.setNombre(entity.getNombre());
        response.setDescripcion(entity.getDescripcion());
        response.setPrecio(entity.getPrecio());
        response.setStock(entity.getStock());
        response.setCategoria(entity.getCategoria());
        response.setCodigo(entity.getCodigo());

        productRepository.saveAndFlush(response);
        return response;
    }

    public boolean delete(Long id){
        var response = productRepository.findById(id)
        .orElse(null);

        if(response == null) return false;
        productRepository.deleteById(id);

        return true;
    }

    public List<GetAllProductResponse> getAll(){
        return productRepository.findAll()
            .stream()
            .map(GetAllProductResponse::toDto)
            .collect(Collectors.toList());
    }

    public BasePageableDto<GetAllProductPageableResponse> getAllPageable(int pageNumber, int pageSize, String sortColumn, String sortOrder, String nombre, String codigo){

        Sort sorting = Sort.by(sortOrder.equals("asc")? Direction.ASC : Direction.DESC , sortColumn);

        Pageable pageable = PageRequest.of(pageNumber, pageSize, sorting);

        return BasePageableDto.toGetAllProductPageableResponse( productRepository.findAllWithPagingAndCustomFilter(nombre, codigo, pageable));
    }

    public GetProductByIdResponse getById(Long id){
        var response = productRepository
            .findById(id)
            .orElse(null);
        if(response == null) return null;

        return GetProductByIdResponse.toDto(response);
    }

    @Transactional(readOnly = false, timeout = 10)
    public Product updateCodigo(Long id, String codigo) throws NotFoundException {
        var product = productRepository.findById(id)
            .orElseThrow(() -> new NotFoundException());
        product.setCodigo(codigo);
        productRepository.save(product);
        return product;
    } 

    
}
