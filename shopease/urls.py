
from django.contrib import admin
from django.urls import path
from core import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('seller/', views.seller_dashboard, name='seller_dashboard'),
    path('seller/add-product/', views.add_product, name='add_product'),
    path('seller/edit-product/<int:product_id>/', views.edit_product, name='edit_product'),
    path('seller/delete-product/<int:product_id>/', views.delete_product, name='delete_product'),
    path('products/', views.product_list, name='product_list'),
    path('products/json/', views.product_list_json, name='product_list_json'),
    path('cart/add/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.view_cart, name='view_cart'),
    path('cart/update/<int:cart_item_id>/<str:action>/', views.update_cart_quantity, name='update_cart_quantity'),
    path('cart/remove/<int:cart_item_id>/', views.remove_from_cart, name='remove_from_cart'),
    path('checkout/', views.checkout, name='checkout'),
    path('order-confirmation/<int:order_id>/', views.order_confirmation, name='order_confirmation'),
    path('orders/', views.order_history, name='order_history'),
    path('order/<int:order_id>/', views.order_detail, name='order_detail'),
    path('profile/', views.buyer_profile, name='buyer_profile'),
    path('review/add/<int:product_id>/', views.add_review, name='add_review'),
    path('order/update-status/<int:order_id>/', views.update_order_status, name='update_order_status'),
    path('notifications/', views.notifications, name='notifications'),
    path('notifications/mark-as-read/<int:notification_id>/', views.mark_as_read, name='mark_as_read'),
    path('notifications/clear/', views.clear_notifications, name='clear_notifications'),
    path('seller/sales-data/', views.sales_data, name='sales_data'),
    path('seller/profile/', views.seller_profile, name='seller_profile'),
    # Seller notifications
    path('seller/notifications/', views.seller_notifications, name='seller_notifications'),
    path('seller/notifications/mark-as-read/<int:notification_id>/', views.seller_mark_as_read, name='seller_mark_as_read'),
    path('seller/notifications/clear/', views.seller_clear_notifications, name='seller_clear_notifications'),
    # CSV exports
    path('seller/export_orders_csv/', views.export_orders_csv, name='export_orders_csv'),
    path('seller/export_products_csv/', views.export_products_csv, name='export_products_csv'),
    # New product detail URL
    path('product/<int:product_id>/', views.product_detail, name='product_detail'),
    path('chatbot/', views.chatbot, name='chatbot'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)