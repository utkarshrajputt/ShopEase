from django.contrib import admin
from .models import Category, Product, User, Order, OrderItem, Cart, CartItem

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'id')  # Show name and ID in the list
    search_fields = ('name',)      # Add a search bar
    ordering = ('name',)           # Sort alphabetically

admin.site.register(Product)
admin.site.register(User)
admin.site.register(Order)
admin.site.register(OrderItem)
admin.site.register(Cart)
admin.site.register(CartItem)