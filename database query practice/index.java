@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

    @Query("SELECT o FROM Order o JOIN o.user u WHERE u.id = :userId")
    List<Order> findOrdersByUserId(@Param("userId") Long userId);

    @Query("SELECT o FROM User u LEFT JOIN u.orders o WHERE u.id = :userId")
    List<Order> findOrdersByUserIdWithLeftJoin(@Param("userId") Long userId);
    @Query("SELECT o FROM * USER u FULL JOIN u.contacts  u.address o WHERE u.id = :userId")
}


