package pe.idat.dsi.dcn.product_api.models;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonManagedReference;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name="products")

public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "nombre", length = 100, nullable = false )
    private String nombre;
    @Column(name = "descripcion", length=300, nullable = false)
    private String descripcion;
    @Column(name = "precio", nullable = false)
    private Double precio;
    @Column(name = "stock", nullable = false)
    private Integer stock;
    @Column(name="categoria", length =100, nullable = false)
    private String categoria;
    @Column(name = "codigo", length = 50, unique = true, nullable = false)
    private String codigo;

    @JsonManagedReference
    @OneToMany(mappedBy ="product")
    private List<Address> addresses;

}
