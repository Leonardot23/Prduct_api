package pe.idat.dsi.dcn.product_api.dtos;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import pe.idat.dsi.dcn.product_api.models.Product;


@Data
@NoArgsConstructor
@AllArgsConstructor

public class GetProductByIdResponse {
    private Long id;
    private String nombre;
    private String categoria;
    private String codigoid;
    private int addresses;

    public static GetProductByIdResponse toDto(Product entity){
        return new GetProductByIdResponse(
            entity.getId(), 
            entity.getNombre(),
            entity.getCategoria(), 
            entity.getCodigo(), 
            entity.getAddresses().size()
            );
    }
}
