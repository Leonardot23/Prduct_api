package pe.idat.dsi.dcn.product_api.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateCodigoProductRequest {
    private Long id;
    private String codigo;
}
