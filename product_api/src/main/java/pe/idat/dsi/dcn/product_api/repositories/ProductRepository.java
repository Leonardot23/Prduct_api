package pe.idat.dsi.dcn.product_api.repositories;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import pe.idat.dsi.dcn.product_api.models.Product;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {

    @Query("SELECT c FROM Product c WHERE c.nombre LIKE %:nombre% AND c.codigo LIKE %:codigo%")
    Page<Product> findAllWithPagingAndCustomFilter(@Param("nombre")String name, @Param("codigo") String nid, Pageable pageable);
}