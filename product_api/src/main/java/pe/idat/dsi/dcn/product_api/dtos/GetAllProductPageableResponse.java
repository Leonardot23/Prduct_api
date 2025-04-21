package pe.idat.dsi.dcn.product_api.dtos;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import pe.idat.dsi.dcn.product_api.models.Product;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class GetAllProductPageableResponse {
    private Long id;
    private String nombre;
    private String categoria;
    private String codigoid;
    private int addresses;

    public static GetAllProductPageableResponse toDto(Product entity){
        return new GetAllProductPageableResponse(
            entity.getId(), 
            entity.getNombre(),
            entity.getCategoria(), 
            entity.getCodigo(), 
            entity.getAddresses().size()
            );
    }
}
