package pe.idat.dsi.dcn.product_api.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import pe.idat.dsi.dcn.product_api.models.Product;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class GetAllProductResponse {
    private Long id;
    private String fullname;
    private String codigo;

    public static GetAllProductResponse toDto(Product product){
        return new GetAllProductResponse(
            product.getId(), 
            product.getNombre() + " " + product.getCategoria(),
            product.getCodigo()
            );
    }
}
