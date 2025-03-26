from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Sum, Avg, Count
from django.http import JsonResponse
from .forms import BuyerProfileForm, UserRegisterForm, UserLoginForm, ProductForm
from .models import Notification, Product, Category, Cart, CartItem, Order, OrderItem, Review, SellerActivity, SellerProfile, User
from datetime import timedelta
from django.utils import timezone
from django.core.paginator import Paginator

from django.shortcuts import render, redirect
from django.core.mail import send_mail, EmailMultiAlternatives
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.forms import SetPasswordForm
from django.template.loader import render_to_string

User = get_user_model()

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            # Generate token and UID
            token_generator = PasswordResetTokenGenerator()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)

            # Create reset link
            reset_url = request.build_absolute_uri(
                reverse('reset_password', kwargs={'uidb64': uid, 'token': token})
            )

            # Prepare email content
            plain_message = f'Click the link below to reset your ShopEase password:\n\n{reset_url}\n\nThis link will expire in 48 hours.'
            html_message = render_to_string('emails/password_reset.html', {
                'reset_url': reset_url,
                'user_name': user.username,  # Optional: Personalize with username
                'site_name': 'ShopEase',
            })

            # Send email with both plain and HTML versions
            email_subject = 'ShopEase Password Reset'
            email_from = 'your-email@gmail.com'  # Replace with your Gmail address
            email = EmailMultiAlternatives(
                subject=email_subject,
                body=plain_message,
                from_email=email_from,
                to=[email],
            )
            email.attach_alternative(html_message, 'text/html')
            email.send()

            messages.success(request, 'A password reset link has been sent to your email.')
            return redirect('login')
        else:
            messages.error(request, 'No user found with this email address.')
            return redirect('forgot_password')

    return render(request, 'forgot_password.html')

def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    token_generator = PasswordResetTokenGenerator()
    if user is not None and token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully. Please log in.')
                return redirect('login')
            else:
                for error in form.errors.values():
                    messages.error(request, error)
        else:
            form = SetPasswordForm(user)
        return render(request, 'reset_password.html', {'form': form})
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('forgot_password')

def home(request):
    categories = Category.objects.all()
    top_products = Product.objects.order_by('-created_at')[:4]  # Top 4 recent products
    # Featured deals: Products with stock <= 10 (low stock) or created in the last 7 days
    featured_deals = Product.objects.filter(is_featured=True).order_by('-created_at')[:6]
    context = {
        'categories': categories,
        'top_products': top_products,
        'featured_deals': featured_deals,
    }
    if request.user.is_authenticated:
        context['unread_notifications'] = Notification.objects.filter(user=request.user, is_read=False).count()
    return render(request, 'home.html', context)


# myapp/views.py
def product_detail(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    reviews = Review.objects.filter(product=product)
    review_exists = False
    if request.user.is_authenticated and request.user.role == 'buyer':
        review_exists = Review.objects.filter(product=product, user=request.user).exists()
    context = {
        'product': product,
        'reviews': reviews,
        'review_exists': review_exists
    }
    return render(request, 'product_detail.html', context)

def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! Please log in.')
            return redirect('login')
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        if request.user.role == 'admin':
            return redirect('/admin/')
        elif request.user.role == 'seller':
            return redirect('seller_dashboard')  # Redirect to /seller/
        else:  # buyer
            return redirect('home')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            if user.role == 'admin':
                return redirect('/admin/')
            elif user.role == 'seller':
                return redirect('seller_dashboard')  # Redirect to /seller/
            else:  # buyer
                return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'login.html')

def logout_view(request):
    logout(request)  # This should now work with the import
    messages.success(request, 'You have been logged out.')
    return redirect('home')



@login_required
def add_product(request):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can add products.')
        return redirect('home')
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save(commit=False)
            product.seller = request.user
            product.save()
            messages.success(request, 'Product added successfully!')
            return redirect('seller_dashboard')
    else:
        form = ProductForm()
    return render(request, 'add_product.html', {'form': form})

@login_required
def edit_product(request, product_id):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can edit products.')
        return redirect('home')
    product = get_object_or_404(Product, id=product_id, seller=request.user)
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            form.save()
            messages.success(request, 'Product updated successfully!')
            return redirect('seller_dashboard')
    else:
        form = ProductForm(instance=product)
    return render(request, 'edit_product.html', {'form': form, 'product': product})

@login_required
def delete_product(request, product_id):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can delete products.')
        return redirect('home')
    product = get_object_or_404(Product, id=product_id, seller=request.user)
    if request.method == 'POST':
        product.delete()
        messages.success(request, 'Product deleted successfully!')
        return redirect('seller_dashboard')
    return render(request, 'delete_product.html', {'product': product})

def product_list(request):
    products = Product.objects.all()
    query = request.GET.get('q', '')
    category = request.GET.get('category', '')
    min_price = request.GET.get('min_price', '')
    max_price = request.GET.get('max_price', '')

    if query:
        products = products.filter(name__icontains=query)
    if category:
        products = products.filter(category__name__iexact=category)  # Case-insensitive match
    if min_price:
        products = products.filter(price__gte=min_price)
    if max_price:
        products = products.filter(price__lte=max_price)

    products = products.annotate(
        avg_rating=Avg('review__rating'),
        review_count=Count('review')
    )

    paginator = Paginator(products, 9)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    context = {
        'products': page_obj,
        'categories': Category.objects.all(),
        'query': query,
        'selected_category': category,
        'min_price': min_price,
        'max_price': max_price,
        'page_obj': page_obj,
    }
    return render(request, 'product_list.html', context)

import logging

logger = logging.getLogger(__name__)

def product_list_json(request):
    logger.info(f"product_list_json called for user: {request.user} (authenticated: {request.user.is_authenticated})")
    products = Product.objects.all()
    query = request.GET.get('q', '')
    category = request.GET.get('category', '')
    min_price = request.GET.get('min_price', '')
    max_price = request.GET.get('max_price', '')
    page = request.GET.get('page', 1)

    if query:
        products = products.filter(name__icontains=query)
    if category:
        products = products.filter(category__name__iexact=category)
    if min_price:
        products = products.filter(price__gte=min_price)
    if max_price:
        products = products.filter(price__lte=max_price)

    products = products.annotate(
        avg_rating=Avg('review__rating'),
        review_count=Count('review')
    )

    paginator = Paginator(products, 9)
    page_obj = paginator.get_page(page)

    data = {
        'products': [
            {
                'id': product.id,
                'name': product.name,
                'description': product.description or '',
                'price': float(product.price),
                'stock': product.stock,
                'image': product.image.url if product.image else '',
                'avg_rating': float(product.avg_rating) if product.avg_rating else None,
                'review_count': product.review_count,
            } for product in page_obj
        ],
        'has_previous': page_obj.has_previous(),
        'has_next': page_obj.has_next(),
        'page': page_obj.number,
        'num_pages': paginator.num_pages,
    }
    logger.info(f"Returning {len(data['products'])} products for page {page}")
    return JsonResponse(data)
    
@login_required
def add_to_cart(request, product_id):
    if not request.user.is_authenticated or request.user.role != 'buyer':
        messages.error(request, 'Please log in as a buyer to add items to your cart.')
        return redirect('login')
    product = get_object_or_404(Product, id=product_id, stock__gt=0)
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_item, item_created = CartItem.objects.get_or_create(cart=cart, product=product)
    if not item_created:
        if product.stock >= cart_item.quantity + 1:
            cart_item.quantity += 1
            cart_item.save()
        else:
            messages.error(request, f'Only {product.stock} left in stock.')
    else:
        messages.success(request, f'{product.name} added to cart!')
    return redirect('product_list')

@login_required
def view_cart(request):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can view the cart.')
        return redirect('home')
    cart, created = Cart.objects.get_or_create(user=request.user)
    cart_items = cart.items.all()
    subtotal = sum(item.quantity * item.product.price for item in cart_items)
    shipping = 50 if subtotal > 0 else 0  # Example flat rate
    total = subtotal + shipping
    
    # Pre-calculate item totals
    cart_items_with_totals = [
        {'item': item, 'total': item.quantity * item.product.price}
        for item in cart_items
    ]
    
    context = {
        'cart_items': cart_items_with_totals,  # List of dicts with item and total
        'subtotal': subtotal,
        'shipping': shipping,
        'total': total,
    }
    return render(request, 'cart.html', context)  # Changed to cart.html

@login_required
def update_cart_quantity(request, cart_item_id, action):
    if request.user.role != 'buyer':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    cart_item = get_object_or_404(CartItem, id=cart_item_id, cart__user=request.user)
    if action == 'increase':
        cart_item.quantity += 1
    elif action == 'decrease' and cart_item.quantity > 1:
        cart_item.quantity -= 1
    cart_item.save()

    # Recalculate totals
    cart = cart_item.cart
    subtotal = sum(item.quantity * item.product.price for item in cart.items.all())
    shipping = 50 if subtotal > 0 else 0
    total = subtotal + shipping

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'quantity': cart_item.quantity,
            'subtotal': float(subtotal),
            'shipping': float(shipping),
            'total': float(total),
            'item_total': float(cart_item.quantity * cart_item.product.price),
        })
    return redirect('view_cart')

@login_required
def remove_from_cart(request, cart_item_id):
    if request.user.role != 'buyer':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    cart_item = get_object_or_404(CartItem, id=cart_item_id, cart__user=request.user)
    cart_item.delete()

    # Recalculate totals
    cart = Cart.objects.get(user=request.user)
    subtotal = sum(item.quantity * item.product.price for item in cart.items.all())
    shipping = 50 if subtotal > 0 else 0
    total = subtotal + shipping

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'subtotal': float(subtotal),
            'shipping': float(shipping),
            'total': float(total),
            'removed': True,
        })
    return redirect('view_cart')

# Add these imports at the top of views.py
import razorpay
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

# Initialize Razorpay client (you can add this at the top of views.py or in settings.py)
razorpay_client = razorpay.Client(auth=("rzp_test_zx2S7Ke0lkJO2J", "8TSDZqbzX1A9LABvuaw7K4Is"))

# Update the checkout view
@login_required
def checkout(request):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can checkout.')
        return redirect('home')
    
    cart = Cart.objects.get(user=request.user)
    cart_items = cart.items.all()
    if not cart_items:
        messages.error(request, 'Your cart is empty.')
        return redirect('view_cart')
    
    # Check stock availability
    for item in cart_items:
        if item.quantity > item.product.stock:
            messages.error(request, f'Sorry, only {item.product.stock} of {item.product.name} left in stock.')
            return redirect('view_cart')

    # Pre-calculate totals
    cart_items_with_totals = [
        {'item': item, 'total': item.quantity * item.product.price}
        for item in cart_items
    ]
    subtotal = sum(item['total'] for item in cart_items_with_totals)
    shipping = 50 if subtotal > 0 else 0
    total = subtotal + shipping

    if request.method == 'POST':
        payment_method = request.POST.get('payment_method', '').strip()
        shipping_address = request.POST.get('shipping_address', '').strip()
        
        # Validate shipping address
        if not shipping_address:
            messages.error(request, 'Shipping address is required.')
            return render(request, 'checkout.html', {
                'cart_items': cart_items_with_totals,
                'subtotal': subtotal,
                'shipping': shipping,
                'total': total,
            })
        if len(shipping_address) < 10:
            messages.error(request, 'Shipping address must be at least 10 characters long.')
            return render(request, 'checkout.html', {
                'cart_items': cart_items_with_totals,
                'subtotal': subtotal,
                'shipping': shipping,
                'total': total,
            })

        if payment_method == "Cash on Delivery":
            # Create order for Cash on Delivery
            order = Order.objects.create(
                user=request.user,
                total_amount=total,
                shipping_address=shipping_address,
                payment_method='Cash on Delivery',
                status='pending'
            )
            for cart_item in cart_items_with_totals:
                OrderItem.objects.create(
                    order=order,
                    product=cart_item['item'].product,
                    quantity=cart_item['item'].quantity,
                    price=cart_item['total']
                )
                product = cart_item['item'].product
                product.stock -= cart_item['item'].quantity
                product.save()
                # Notify the seller of the new order
                Notification.objects.create(
                    user=product.seller,
                    message=f"A new order #{order.id} has been placed for your product: {product.name}.",
                    related_order=order
                )
            
            cart.items.all().delete()
            messages.success(request, 'Order placed successfully!')
            return redirect('order_confirmation', order_id=order.id)
        else:
            # For Pay Online, we handle it via AJAX in create_razorpay_order
            messages.error(request, 'Invalid payment method.')
            return redirect('checkout')
    
    context = {
        'cart_items': cart_items_with_totals,
        'subtotal': subtotal,
        'shipping': shipping,
        'total': total,
        'default_shipping_address': request.user.address if request.user.address else '',
        'razorpay_key_id': "rzp_test_zx257Ke0lk0J02",  # Pass the key_id to the template
    }
    return render(request, 'checkout.html', context)

from decimal import Decimal  # Add this import at the top of views.py

@login_required
def create_razorpay_order(request):
    if request.user.role != 'buyer':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=400)
    
    try:
        # Parse the request body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {str(e)}")
            return JsonResponse({'error': 'Invalid request data. Check your input.'}, status=400)

        shipping_address = data.get('shipping_address', '').strip()
        # Convert total to Decimal instead of float
        total = Decimal(str(data.get('total', '0')))  # Use str() to handle float input safely

        if not shipping_address or len(shipping_address) < 10:
            return JsonResponse({'error': 'Shipping address must be at least 10 characters long.'}, status=400)

        # Validate total
        if total <= 0:
            logger.error(f"Invalid total amount: {total}")
            return JsonResponse({'error': 'Total amount must be greater than 0.'}, status=400)

        # Create the order in the database
        try:
            cart = Cart.objects.get(user=request.user)
        except Cart.DoesNotExist:
            logger.error(f"Cart not found for user: {request.user.username}")
            return JsonResponse({'error': 'Cart not found. Add items to your cart first.'}, status=400)

        cart_items = cart.items.all()
        if not cart_items:
            logger.error(f"Cart is empty for user: {request.user.username}")
            return JsonResponse({'error': 'Your cart is empty.'}, status=400)

        # Check stock availability
        for item in cart_items:
            if item.quantity > item.product.stock:
                logger.error(f"Stock issue: {item.product.name} has {item.product.stock} but {item.quantity} requested")
                return JsonResponse({'error': f'Sorry, only {item.product.stock} of {item.product.name} left in stock.'}, status=400)

        # Pre-calculate totals (for consistency)
        cart_items_with_totals = [
            {'item': item, 'total': item.quantity * item.product.price}
            for item in cart_items
        ]
        subtotal = sum(item['total'] for item in cart_items_with_totals)
        shipping = Decimal('50') if subtotal > 0 else Decimal('0')  # Ensure shipping is also a Decimal
        total_calculated = subtotal + shipping

        # Log the totals for debugging
        logger.debug(f"Calculated total: {total_calculated}, Received total: {total}")

        # Now both total_calculated and total are Decimals, so this comparison will work
        if abs(total_calculated - total) > Decimal('0.01'):  # Allow for minor differences
            logger.error(f"Total mismatch: calculated {total_calculated}, received {total}")
            return JsonResponse({'error': 'Total amount mismatch.'}, status=400)

        # Validate Razorpay amount (must be at least ₹1)
        amount_in_paise = int(total * 100)
        if amount_in_paise < 100:
            logger.error(f"Razorpay amount too low: {amount_in_paise} paise (minimum 100 paise)")
            return JsonResponse({'error': 'Order amount must be at least ₹1.'}, status=400)

        # Create the order
        try:
            order = Order.objects.create(
                user=request.user,
                total_amount=total,
                shipping_address=shipping_address,
                payment_method='Online Payment',
                status='pending'
            )
        except Exception as e:
            logger.error(f"Failed to create Order: {str(e)}")
            return JsonResponse({'error': 'Failed to create order in database.'}, status=500)

        try:
            for cart_item in cart_items_with_totals:
                OrderItem.objects.create(
                    order=order,
                    product=cart_item['item'].product,
                    quantity=cart_item['item'].quantity,
                    price=cart_item['total']
                )
                product = cart_item['item'].product
                product.stock -= cart_item['item'].quantity
                product.save()
                # Notify the seller of the new order
                Notification.objects.create(
                    user=product.seller,
                    message=f"A new order #{order.id} has been placed for your product: {product.name}.",
                    related_order=order
                )
        except Exception as e:
            logger.error(f"Failed to create OrderItems or update stock: {str(e)}")
            # Roll back the order if OrderItems creation fails
            order.delete()
            return JsonResponse({'error': 'Failed to process order items.'}, status=500)

        # Clear the cart
        try:
            cart.items.all().delete()
        except Exception as e:
            logger.error(f"Failed to clear cart: {str(e)}")
            # Not critical, but log it
            pass

        # Create Razorpay order
        try:
            razorpay_order = razorpay_client.order.create({
                "amount": amount_in_paise,
                "currency": "INR",
                "payment_capture": 1  # Auto-capture payment
            })
        except razorpay.errors.BadRequestError as e:
            logger.error(f"Razorpay BadRequestError: {str(e)}")
            # Roll back the order if Razorpay fails
            order.delete()
            return JsonResponse({'error': f'Razorpay error: {str(e)}'}, status=500)
        except Exception as e:
            logger.error(f"Razorpay general error: {str(e)}")
            # Roll back the order if Razorpay fails
            order.delete()
            return JsonResponse({'error': 'Failed to create Razorpay order.'}, status=500)

        return JsonResponse({
            'razorpay_order_id': razorpay_order['id'],
            'amount': amount_in_paise,
            'order_id': order.id,  # Pass the Django order ID for redirection
        })
    except Exception as e:
        logger.error(f"Unexpected error in create_razorpay_order: {str(e)}")
        return JsonResponse({'error': 'Failed to create order. Try again.'}, status=500)

@login_required
def seller_notifications(request):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can view notifications.')
        return redirect('home')
    
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications = Notification.objects.filter(user=request.user, is_read=False).count()
    context = {
        'notifications': notifications,
        'unread_notifications': unread_notifications,
    }
    return render(request, 'seller_notifications.html', context)

@login_required
def seller_mark_as_read(request, notification_id):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can mark notifications as read.')
        return redirect('home')
    
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    if request.method == 'POST':
        notification.is_read = True
        notification.save()
        messages.success(request, 'Notification marked as read.')
    return redirect('seller_notifications')

@login_required
def seller_clear_notifications(request):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can clear notifications.')
        return redirect('home')
    
    if request.method == 'POST':
        Notification.objects.filter(user=request.user).delete()
        messages.success(request, 'All notifications have been cleared.')
    return redirect('seller_notifications')

@login_required
def notifications(request):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can view notifications.')
        return redirect('home')
    
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications = Notification.objects.filter(user=request.user, is_read=False).count()
    context = {
        'notifications': notifications,
        'unread_notifications': unread_notifications,
    }
    return render(request, 'notifications.html', context)

@login_required
def clear_notifications(request):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can clear notifications.')
        return redirect('home')
    
    if request.method == 'POST':
        # Delete all notifications for the user
        Notification.objects.filter(user=request.user).delete()
        messages.success(request, 'All notifications have been cleared.')
    return redirect('notifications')

# Add this new view for marking notifications as read
@login_required
def mark_as_read(request, notification_id):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can view notifications.')
        return redirect('home')
    
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    if request.method == 'POST':
        notification.is_read = True
        notification.save()
        messages.success(request, 'Notification marked as read.')
    return redirect('notifications')

@login_required
def order_confirmation(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    
    # Calculate totals for email
    order_items = order.items.all()
    items_with_totals = [
        {'item': item, 'total': item.quantity * item.price}
        for item in order_items
    ]
    subtotal = sum(item['total'] for item in items_with_totals)
    shipping = 50 if subtotal > 0 else 0
    total = subtotal + shipping

    # Prepare email content with Rupees sign
    plain_message = (
        f'Your ShopEase order (ID: {order.id}) has been confirmed.\n\n'
        f'Order Details:\n'
        f'Order ID: #{order.id}\n'
        f'Shipping Address: {order.shipping_address}\n'
        f'Subtotal: ₹{subtotal}\n'
        f'Shipping: ₹{shipping}\n'
        f'Total: ₹{total}\n'
        f'Status: {order.status}\n'
        f'Created: {order.created_at}\n\n'
        f'Thank you for shopping with us!'
    )
    html_message = render_to_string('emails/order_confirmation.html', {
        'order_id': order.id,
        'shipping_address': order.shipping_address,
        'subtotal': subtotal,
        'shipping': shipping,
        'total': total,
        'status': order.status,
        'created_at': order.created_at,
        'user_name': request.user.username,
        'site_name': 'ShopEase',
        'order_items': items_with_totals,
    })

    # Send email
    email_subject = f'ShopEase Order Confirmation - #{order.id}'
    email_from = 'your-email@gmail.com'  # Replace with your Gmail address
    email = EmailMultiAlternatives(
        subject=email_subject,
        body=plain_message,
        from_email=email_from,
        to=[request.user.email],
    )
    email.attach_alternative(html_message, 'text/html')
    email.send()

    # Create notification
    Notification.objects.create(
        user=request.user,
        message=f'Your order #{order.id} has been confirmed.',
        related_order=order
    )

    messages.success(request, f'Order #{order.id} confirmed! Details sent to your email.')
    context = {'order': order}
    return render(request, 'order_confirmation.html', context)

@login_required
def order_history(request):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can view order history.')
        return redirect('home')
    
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    
    context = {
        'orders': orders,
    }
    return render(request, 'order_history.html', context)

@login_required
def order_detail(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    
    if request.user.role == 'buyer' and order.user != request.user:
        messages.error(request, 'You can only view your own orders.')
        return redirect('order_history')
    elif request.user.role == 'seller' and not order.items.filter(product__seller=request.user).exists():
        messages.error(request, 'You can only view orders containing your products.')
        return redirect('seller_dashboard')
    elif request.user.role not in ['buyer', 'seller']:
        messages.error(request, 'Unauthorized access.')
        return redirect('home')

    order_items = order.items.all()
    # Precompute totals and review status for each item
    items_with_details = [
        {
            'item': item,
            'total': item.quantity * item.price,
            'has_reviewed': item.product.review_set.filter(user=request.user).exists() if request.user.role == 'buyer' else False
        }
        for item in order_items
    ]
    subtotal = sum(item['total'] for item in items_with_details)
    shipping = 50 if subtotal > 0 else 0
    total = subtotal + shipping

    context = {
        'order': order,
        'order_items': items_with_details,
        'subtotal': subtotal,
        'shipping': shipping,
        'total': total,
    }
    return render(request, 'order_detail.html', context)


@login_required
def buyer_profile(request):
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can access this page.')
        return redirect('home')
    
    if request.method == 'POST':
        form = BuyerProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('buyer_profile')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = BuyerProfileForm(instance=request.user)
    
    return render(request, 'buyer_profile.html', {'form': form})

@login_required
def seller_dashboard(request):
    if request.user.role != 'seller':
        messages.error(request, 'Only sellers can access this page.')
        return redirect('home')
    
    products = Product.objects.filter(seller=request.user)
    orders = Order.objects.filter(items__product__seller=request.user).distinct().order_by('-created_at')
    recent_activities = SellerActivity.objects.filter(seller=request.user).order_by('-timestamp')[:5]
    
    # Apply filters to orders
    status = request.GET.get('status', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    buyer = request.GET.get('buyer', '')
    order_id = request.GET.get('order_id', '')

    filtered_orders = orders
    if status:
        filtered_orders = filtered_orders.filter(status=status)
    if start_date:
        filtered_orders = filtered_orders.filter(created_at__gte=start_date)
    if end_date:
        filtered_orders = filtered_orders.filter(created_at__lte=end_date)
    if buyer:
        filtered_orders = filtered_orders.filter(user__username__icontains=buyer)
    if order_id:
        filtered_orders = filtered_orders.filter(id=order_id)

    # Paginate orders
    orders_paginator = Paginator(filtered_orders, 10)
    orders_page_number = request.GET.get('orders_page', 1)
    orders_page_obj = orders_paginator.get_page(orders_page_number)

    # Paginate products
    products_paginator = Paginator(products, 10)
    products_page_number = request.GET.get('products_page', 1)
    products_page_obj = products_paginator.get_page(products_page_number)

    # Sales analytics
    completed_orders = filtered_orders.filter(status__in=['shipped', 'delivered'])
    total_sales = OrderItem.objects.filter(
        product__seller=request.user,
        order__status__in=['shipped', 'delivered']
    ).aggregate(total=Sum('price'))['total'] or 0
    
    total_products = products.count()
    pending_orders = filtered_orders.filter(status='pending').count()
    current_month = timezone.now().month
    current_year = timezone.now().year
    revenue_this_month = OrderItem.objects.filter(
        product__seller=request.user,
        order__status__in=['shipped', 'delivered'],
        order__created_at__month=current_month,
        order__created_at__year=current_year
    ).aggregate(total=Sum('price'))['total'] or 0
    average_order_value = completed_orders.aggregate(avg=Avg('total_amount'))['avg'] or 0
    
    top_product = products.annotate(
        total_sold=Sum('orderitem__quantity', filter=Q(orderitem__order__status__in=['shipped', 'delivered']))
    ).order_by('-total_sold').first()
    
    low_stock_products = products.filter(stock__lte=5)
    
    # Calculate unread notifications for the seller
    unread_notifications = Notification.objects.filter(user=request.user, is_read=False).count()
    
    context = {
        'products': products_page_obj,
        'orders': filtered_orders,
        'total_sales': total_sales,
        'total_products': total_products,
        'pending_orders': pending_orders,
        'revenue_this_month': revenue_this_month,
        'average_order_value': average_order_value,
        'top_product': top_product,
        'low_stock_products': low_stock_products,
        'status': status,
        'start_date': start_date,
        'end_date': end_date,
        'buyer': buyer,
        'order_id': order_id,
        'orders_page_obj': orders_page_obj,
        'products_page_obj': products_page_obj,
        'unread_notifications': unread_notifications,
        'recent_activities': recent_activities,
    }
    return render(request, 'seller_dashboard.html', context)

@login_required
def seller_profile(request):
    profile, created = SellerProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        profile.business_name = request.POST.get('business_name', '')
        profile.contact_email = request.POST.get('contact_email', '')
        profile.shipping_policy = request.POST.get('shipping_policy', '')
        profile.save()
        messages.success(request, "Profile updated successfully!")
        return redirect('seller_profile')
    return render(request, 'seller_profile.html', {'profile': profile})

import logging
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Order, Notification, SellerActivity
from django.conf import settings

logger = logging.getLogger(__name__)

@login_required
def update_order_status(request, order_id):
    if request.user.role != 'seller':
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    # Ensure the order belongs to the seller (via the products in OrderItem)
    order = get_object_or_404(Order, id=order_id, items__product__seller=request.user)

    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status in dict(Order.STATUS_CHOICES):
            order.status = new_status
            order.save()

            # Create notification for the buyer based on status
            if new_status == 'shipped':
                Notification.objects.create(
                    user=order.user,
                    message=f'Your order #{order.id} has been shipped.',
                    related_order=order
                )
            elif new_status == 'delivered':
                Notification.objects.create(
                    user=order.user,
                    message=f'Your order #{order.id} has been delivered.',
                    related_order=order
                )
                # Add review reminder for each product in the order
                for item in order.items.all():
                    Notification.objects.create(
                        user=order.user,
                        message=f"You’ve received your order #{order.id}. Share your feedback on {item.product.name}!",
                        related_order=order
                    )
            elif new_status == 'cancelled':
                Notification.objects.create(
                    user=order.user,
                    message=f'Your order #{order.id} has been cancelled.',
                    related_order=order
                )

            # Log the seller activity since the update was successful
            SellerActivity.objects.create(
                seller=request.user,
                action=f"Updated order #{order_id} status to {new_status}"
            )

            # Send email to buyer about the status update
            email_sent = False
            if order.user.email:  # Check if the buyer has an email
                order_url = request.build_absolute_uri(reverse('order_detail', kwargs={'order_id': order.id}))
                plain_message = (
                    f'Your ShopEase order (ID: {order.id}) status has been updated.\n\n'
                    f'Order Details:\n'
                    f'Order ID: #{order.id}\n'
                    f'New Status: {order.status}\n'
                    f'Updated At: {timezone.now()}\n\n'
                    f'View your order here: {order_url}\n\n'
                    f'Thank you for shopping with us!'
                )
                html_message = render_to_string('emails/order_status_update.html', {
                    'order_id': order.id,
                    'status': order.status,
                    'updated_at': timezone.now(),
                    'order_url': order_url,
                    'user_name': order.user.username,
                    'site_name': 'ShopEase',
                })

                # Send email
                email_subject = f'ShopEase Order Status Update - #{order.id}'
                email_from = settings.DEFAULT_FROM_EMAIL
                email = EmailMultiAlternatives(
                    subject=email_subject,
                    body=plain_message,
                    from_email=email_from,
                    to=[order.user.email],
                )
                email.attach_alternative(html_message, 'text/html')
                try:
                    email.send()
                    logger.info(f"Status update email sent to {order.user.email} for order #{order.id}")
                    email_sent = True
                except Exception as e:
                    logger.error(f"Failed to send status update email for order #{order.id} to {order.user.email}: {str(e)}")
            else:
                logger.warning(f"No email address found for user {order.user.username} (order #{order.id}). Please update the user's email.")

            # Return success response with email status
            return JsonResponse({
                'success': True,
                'status': new_status,
                'email_sent': email_sent,
            })
        else:
            # Return error if the status is invalid
            return JsonResponse({'error': 'Invalid status'}, status=400)
    
    # Return error for non-POST requests
    return JsonResponse({'error': 'Invalid request'}, status=400)

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Product, Review, OrderItem

@login_required
def add_review(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    if request.user.role != 'buyer':
        messages.error(request, 'Only buyers can leave reviews.')
        return redirect('product_list')

    # Get the order_id from the query parameter (passed from order_detail.html)
    order_id = request.GET.get('order_id')

    # Check if the buyer has purchased the product
    has_purchased = OrderItem.objects.filter(order__user=request.user, product=product).exists()
    if order_id:
        # Optionally, restrict to the specific order
        has_purchased = OrderItem.objects.filter(order__user=request.user, order__id=order_id, product=product).exists()

    # Check for existing review
    review = Review.objects.filter(user=request.user, product=product).first()

    if request.method == 'POST' and has_purchased:
        rating = request.POST.get('rating')
        comment = request.POST.get('comment')
        Review.objects.update_or_create(
            user=request.user,
            product=product,
            defaults={'rating': rating, 'comment': comment}
        )
        messages.success(request, 'Review submitted successfully! Thanks for your feedback.')
        
        # Redirect back to the order detail page if order_id is provided, otherwise to product detail
        if order_id:
            return redirect('order_detail', order_id=order_id)
        return redirect('product_detail', product_id=product.id)

    context = {
        'product': product,
        'has_purchased': has_purchased,
        'review': review,  # Pass the existing review to pre-fill the form
        'order_id': order_id,  # Pass order_id to the template (for the form)
    }
    return render(request, 'add_review.html', context)

from django.http import JsonResponse
from django.db.models.functions import TruncMonth
from datetime import datetime, timedelta

@login_required
def sales_data(request):
    if request.user.role != 'seller':
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    # Monthly sales for the past 6 months
    end_date = timezone.now()
    start_date = end_date - timedelta(days=180)  # 6 months ago
    monthly_sales = (OrderItem.objects
                     .filter(
                         product__seller=request.user,
                         order__status__in=['shipped', 'delivered'],
                         order__created_at__gte=start_date
                     )
                     .annotate(month=TruncMonth('order__created_at'))
                     .values('month')
                     .annotate(total=Sum('price'))
                     .order_by('month'))

    # Prepare data for the line chart
    sales_labels = []
    sales_values = []
    current_date = start_date.replace(day=1)
    while current_date <= end_date:
        sales_labels.append(current_date.strftime('%b %Y'))
        sales_values.append(0)
        current_date = (current_date + timedelta(days=31)).replace(day=1)

    for sale in monthly_sales:
        month_index = sales_labels.index(sale['month'].strftime('%b %Y'))
        sales_values[month_index] = float(sale['total'])

    # Order status distribution for the pie chart
    orders = Order.objects.filter(items__product__seller=request.user).distinct()
    status_counts = orders.values('status').annotate(count=Count('id'))
    status_labels = [status['status'] for status in status_counts]
    status_values = [status['count'] for status in status_counts]

    return JsonResponse({
        'sales': {
            'labels': sales_labels,
            'values': sales_values,
        },
        'status': {
            'labels': status_labels,
            'values': status_values,
        }
    })
    
import csv
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Order
from django.db.models import Prefetch

@login_required
def export_orders_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="orders.csv"'

    writer = csv.writer(response)
    writer.writerow(['Order ID', 'Buyer', 'Date', 'Total', 'Status'])

    # Get orders containing products owned by the seller
    orders = Order.objects.filter(
        items__product__seller=request.user
    ).distinct()  # Use distinct to avoid duplicate orders if multiple items

    for order in orders:
        writer.writerow([
            order.id,
            order.user.username,  # Adjust if buyer is a different field
            order.created_at.strftime('%Y-%m-%d'),
            order.total_amount,
            order.status,
        ])

    return response

@login_required
def export_products_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="products.csv"'

    writer = csv.writer(response)
    writer.writerow(['Product Name', 'Price', 'Stock'])

    products = Product.objects.filter(seller=request.user)
    for product in products:
        writer.writerow([
            product.name,
            product.price,
            product.stock,
        ])

    return response

import requests
import json
from decouple import config
import logging

logger = logging.getLogger(__name__)
from django.http import JsonResponse

def chatbot(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message', '').strip().lower()  # Convert to lowercase for matching

            if not user_message:
                return JsonResponse({'response': 'Please enter a message, genius.'}, status=400)

            # Custom responses for specific intents
            if any(keyword in user_message for keyword in ['reset password', 'forgot password', 'change password']):
                response = """
                To reset your password, follow these steps:
                1. Go to the login page on ShopEase.
                2. Click on the 'Forgot Password?' link.
                3. Enter the email address associated with your account.
                4. Check your inbox (and spam folder) for an email from us.
                5. Follow the link in the email to create a new password.
                """
            elif any(keyword in user_message for keyword in ['shipping time', 'delivery time', 'how long to deliver']):
                response = """
                Shipping and delivery typically take 8-9 business days, depending on your location. We aim to get your order to you as fast as possible—chill, it’s not teleportation yet!
                """
            elif 'return policy' in user_message:
                response = "Our return policy allows returns within 30 days with original packaging. Contact support for details—don’t just yeet it back and expect miracles!"
            elif any(keyword in user_message for keyword in ['track order', 'where’s my order', 'order status']):
                response = """
                Want to stalk your order? Log in, hit 'Order History,' and check the status on the order detail page. If it’s still lost in the void, ping support with your order ID.
                """
            elif any(keyword in user_message for keyword in ['cancel order', 'how to cancel', 'stop order']):
                response = """
                To cancel an order, tough luck if it’s already shipped. If it’s still 'pending,' head to 'Order History,' find your order, and pray there’s a cancel button. Otherwise, email support and beg nicely.
                """
            elif any(keyword in user_message for keyword in ['discount', 'coupon', 'promo code']):
                response = """
                Fishing for discounts? Check the homepage for current promos—or follow ShopEase on X for the latest codes. No, I’m not handing you a secret 90% off deal, nice try!
                """
            elif 'customer support' in user_message or 'contact' in user_message:
                response = """
                Need a human? Email support@shopease.com or tweet at @ShopEaseHelp on X. They’re probably drowning in tickets, so patience is your new best friend.
                """
            elif any(keyword in user_message for keyword in ['review', 'leave feedback', 'rate product']):
                response = """
                Wanna flex your opinion? Go to 'Order History,' find a delivered order, and hit 'Add Review' on the detail page. Don’t see it? Maybe you already ranted—check your reviews!
                """
            else:
                # Default to Hugging Face API for other queries
                API_URL = "https://api-inference.huggingface.co/models/facebook/blenderbot-400M-distill"
                headers = {
                    "Authorization": f"Bearer {config('HF_API_TOKEN')}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "inputs": user_message,
                    "parameters": {
                        "max_length": 100,
                        "min_length": 10,
                        "temperature": 0.7,
                    }
                }

                response = requests.post(API_URL, headers=headers, json=payload, timeout=10)
                response.raise_for_status()
                result = response.json()
                response = result[0]['generated_text'] if result and isinstance(result, list) else 'Sorry, I couldn’t process that. My AI brain’s having a moment.'

            logger.info(f"User input: {user_message}, Bot response: {response}")
            return JsonResponse({'response': response})
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            return JsonResponse({'response': 'API error. Try again later—tech’s being a diva.'}, status=500)
        except Exception as e:
            logger.error(f"Chatbot error: {str(e)}")
            return JsonResponse({'response': 'Something went wrong. Check back when I’ve had my coffee.'}, status=500)
    return JsonResponse({'error': 'Invalid request method. POST it or bust.'}, status=400)