package pe.idat.dsi.dcn.product_api.services;

import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import pe.idat.dsi.dcn.product_api.models.Address;
import pe.idat.dsi.dcn.product_api.repositories.AddressRepository;
import pe.idat.dsi.dcn.product_api.repositories.ProductRepository;

@Service
public class AddressService {
    private AddressRepository addressRepository;
    private ProductRepository productRepository;

    public AddressService(AddressRepository addressRepository, 
    ProductRepository productRepository){
        this.addressRepository = addressRepository;
        this.productRepository = productRepository;
    }

    @Transactional(timeout = 10, readOnly = false)
    public Address insert(Address entity) throws NotFoundException{
        var product = productRepository.findById(entity.getProduct().getId())
        .orElseThrow( () -> new NotFoundException());

        entity.setProduct(product);

        return addressRepository.save(entity);
    }
}
