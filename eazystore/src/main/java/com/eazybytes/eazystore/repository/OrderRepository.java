package com.eazybytes.eazystore.repository;

import com.eazybytes.eazystore.entity.Contact;
import com.eazybytes.eazystore.entity.Customer;
import com.eazybytes.eazystore.entity.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface OrderRepository extends JpaRepository<Order, Long> {

    List<Order> findByCustomerOrderByCreatedAtDesc(Customer customer);
    List<Order> findOrderByOrderStatus(String orderStatus);

//    @Query("Select o from Order o where o.customer=:customer Order By o.createdAt Desc ")
//    List<Order> findOrderByCustomer(@Param("customer") Customer customer);
//
//    @Query("SELECT o from  Order o where o.orderStatus=?1 ")
//    List<Order> findOrdersByOrderStatus(String orderStatus);
//
//    @Query(value ="Select * from orders o where o.customer_id=:customerId Order By o.createdAt Desc ",nativeQuery = true)
//    List<Order> findOrderByCustomerWithNativeQuery(@Param("customerId") Long customerId);
//
//    @Query(value="SELECT * from  orders o where o.order_status=?1 ",nativeQuery = true)
//
//    List<Order> findOrdersByOrderStatusWithNativeQuery(String orderStatus);
    @Transactional
    @Modifying
    @Query("Update Order o set o.orderStatus=:orderStatus ,o.updatedAt=CURRENT TIMESTAMP ,o.updatedBy=:updatedBy where o.orderId=:orderId ")
    int updateOrderStatus(@Param("orderId") Long orderId, @Param("orderStatus")String orderStatus,@Param("updatedBy")String updatedBy);

}


