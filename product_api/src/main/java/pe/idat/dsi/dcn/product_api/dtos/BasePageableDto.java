package pe.idat.dsi.dcn.product_api.dtos;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import pe.idat.dsi.dcn.product_api.models.Product;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class BasePageableDto<T> {
    private int totalElements;
    private int pageNumber;
    private int pageSize;
    private List<T> items;

    public static BasePageableDto<GetAllProductPageableResponse> toGetAllProductPageableResponse(Page<Product> pageable){
        return new BasePageableDto<GetAllProductPageableResponse>(
            Integer.parseInt(Long.toString( pageable.getTotalElements())),
            pageable.getNumber(),
            pageable.getSize(),
            pageable.getContent()
                .stream()
                .map(GetAllProductPageableResponse::toDto)
                .collect(Collectors.toList())
        );
    }
}
