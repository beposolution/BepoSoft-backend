from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from .validators import validate_gst
import re
from django.core.exceptions import ValidationError
from decimal import Decimal
import random
from django.utils.timezone import now 
from datetime import datetime



# Create your models here.


class State(models.Model):
    name = models.CharField(max_length=100)
    province=models.CharField(max_length=30,null=True)
    
    def __str__(self):
        return self.name
    
    class Meta :
        db_table = "State"

class Departments(models.Model):
    name = models.CharField(max_length=100)
    class Meta:
        db_table = "Departments"

    def __str__(self):
        return self.name

class Supervisor(models.Model):
    name = models.CharField(max_length=100)
    department = models.ForeignKey(Departments, on_delete=models.CASCADE)

    class Meta:
        db_table = "Supervisor"

    def __str__(self):
        return self.name


class Family(models.Model):
    name = models.CharField(max_length=100)
    created_at = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta :
        db_table = "Family"
        

class CountryCode(models.Model):
    country_code = models.CharField(max_length=50, blank=True, default="")
    country_name = models.CharField(max_length=100, blank=True, default="")
    
    class Meta:
        db_table = "CountryCode"
        
    def __str__(self):
        return self.country_code
    

class WareHouse(models.Model):
    name=models.CharField(max_length=200)
    address=models.CharField(max_length=500,null=True)
    location=models.CharField(max_length=200)
    country_code = models.ForeignKey(CountryCode, on_delete=models.SET_NULL, null=True, blank=True)
    unique_id = models.CharField(max_length=10, unique=True, blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.unique_id:  # Generate unique_id only if it doesn't exist
            self.unique_id = self.generate_unique_id()
        super().save(*args, **kwargs)

    def generate_unique_id(self):
        prefix = "WH"
        location_code = self.location[:2].upper() if self.location else "XX"
        while True:
            random_number = random.randint(1000, 9999)  # Generate a 4-digit random number
            unique_id = f"{prefix}-{location_code}-{random_number}"
            if not WareHouse.objects.filter(unique_id=unique_id).exists():
                return unique_id
            

class RackDetailsModel(models.Model):
    warehouse = models.ForeignKey(WareHouse, on_delete=models.SET_NULL, null=True, blank=True)
    rack_name = models.CharField(max_length=50, null=True, blank=True)
    number_of_columns = models.PositiveIntegerField(blank=True, null=True)
    column_names = models.JSONField(blank=True, default=list)

    def save(self, *args, **kwargs):
        # Determine prefix like "KA" from warehouse and rack name
        warehouse_initial = self.warehouse.name[0].upper() if self.warehouse and self.warehouse.name else 'W'
        rack_prefix = f"{warehouse_initial}{self.rack_name.upper()}"

        # Rebuild column list only if number increased
        existing = self.column_names or []
        existing_count = len(existing)
        if self.number_of_columns and self.number_of_columns > existing_count:
            for i in range(existing_count + 1, self.number_of_columns + 1):
                existing.append(f"{rack_prefix}{i}")
            self.column_names = existing

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.rack_name} ({self.warehouse.name if self.warehouse else 'No Warehouse'})"
    
    
class ProductCategoryModel(models.Model):
    category_name = models.CharField(max_length=100, null=True, blank=True)
    
    def __str__(self):
        return self.category_name
    
    class Meta:
        db_table = "ProductCategoryModel"
    
    

class User(models.Model):

    eid = models.CharField(max_length=6, unique=True, editable=False)
    name = models.CharField(max_length=100)
    username = models.CharField(max_length=100,unique=True,null=True)
    email = models.EmailField(max_length=100,unique=True)
    phone = models.CharField(max_length=100,unique=True)
    alternate_number = models.CharField(max_length=10, null=True, blank=True)
    password = models.CharField(max_length=100)
    image = models.ImageField(max_length=100, upload_to="staff_images/", null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    allocated_states = models.ManyToManyField(State, blank=True)
    gender = models.CharField(max_length=100, null=True, blank=True)
    marital_status = models.CharField(max_length=100, null=True, blank=True)
    driving_license = models.CharField(max_length=100, null=True, blank=True)
    driving_license_exp_date = models.DateField(null=True, blank=True)
    employment_status = models.CharField(max_length=100, null=True, blank=True) #(Full-time  Part-time Contract)
    designation = models.CharField(max_length=100, null=True, blank=True)
    grade = models.CharField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=500, null=True, blank=True)
    state = models.CharField(max_length=100, null=-True,blank=True)
    country = models.CharField(max_length=100,default='india', null=True, blank=True)
    join_date = models.DateField(null=True, blank=True)
    confirmation_date = models.DateField(null=True, blank=True)
    termination_date = models.DateField(null=True, blank=True)
    supervisor_id = models.ForeignKey(Supervisor, on_delete=models.CASCADE, null=True)
    department_id = models.ForeignKey(Departments, on_delete=models.CASCADE, null=True)
    warehouse_id=models.ForeignKey(WareHouse,on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="users"
    )
    country_code = models.ForeignKey(CountryCode, on_delete=models.SET_NULL, null=True, blank=True)
    signatur_up = models.ImageField(upload_to="signature/",max_length=100,null=True)
    APPROVAL_CHOICES = [
        ('approved', 'Approved'),
        ('disapproved', 'Disapproved'),
    ]
    approval_status = models.CharField(max_length=100, choices=APPROVAL_CHOICES, default='disapproved', null=True)
    family = models.ForeignKey(Family, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Hash password if provided
        if 'password' in kwargs:
            self.password = make_password(kwargs['password'])
        elif not self.pk and self.password:  # Hash password for new user
            self.password = make_password(self.password)

        # Generate unique eid if not already set
        if not self.eid:
            self.eid = self.generate_unique_eid()

        super().save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def generate_unique_eid(self):
        while True:
            eid = str(random.randint(100000, 999999))
            if not User.objects.filter(eid=eid).exists():
                return eid

    class Meta:
        db_table = "User"


class CallLog(models.Model):
    customer_name = models.CharField(max_length=100)
    active_calls = models.PositiveIntegerField(help_text="Number of active calls")
    phone_number = models.CharField(max_length=15)
    call_duration_seconds = models.PositiveIntegerField()
    call_date = models.DateField()
    start_time = models.DateTimeField(help_text="Start time of the call")
    end_time = models.DateTimeField(help_text="End time of the call")
    bill_count = models.PositiveIntegerField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    family_name = models.ForeignKey(Family, on_delete=models.CASCADE, null=True, blank=True)

    def clean(self):
        super().clean()
        # Check if end_time is after start_time
        if self.end_time and self.start_time and self.end_time <= self.start_time:
            raise ValidationError({
                'end_time': "End time must be after start time."
            })

    def __str__(self):
        return f"{self.customer_name} - {self.phone_number}"
    
    class Meta:
        db_table = "calllog"



class Attributes(models.Model):
    created_user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100) 

    def __str__(self):
        return self.name

    class Meta:
        db_table = "attributes"


class ProductAttribute(models.Model):
    attribute = models.ForeignKey(Attributes, on_delete=models.CASCADE)
    value = models.CharField(max_length=255) #ex RED BLACK L M 

    def __str__(self):
        return f"{self.attribute.name}: {self.value}"

    class Meta:
        db_table = "product_attributes" 


class Customers(models.Model):
    CUSTOMER_STATUS = [
        ('customer', 'customer'),
        ('warehouse', 'warehouse'),
    ]
    gst = models.CharField(
        max_length=15,
        null=True,
        blank=True,
        validators=[validate_gst],  
    )
    name = models.CharField(max_length=100)
    manager = models.ForeignKey(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=10, null=True, unique=True)
    alt_phone = models.CharField(max_length=10, null=True, blank=True)
    email = models.EmailField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=500, null=True)
    zip_code = models.CharField(max_length=200, null=True)
    city = models.CharField(max_length=100, null=True)
    state = models.ForeignKey(State, on_delete=models.CASCADE, null=True, blank=True)
    comment = models.CharField(max_length=500, null=True, blank=True)
    created_at = models.DateField(auto_now_add=True)
    customer_status = models.CharField(max_length=200, choices=CUSTOMER_STATUS, default='customer')
    family = models.ForeignKey(Family, on_delete=models.SET_NULL, null=True, blank=True)  # <-- Add this line

    def __str__(self):
        return self.name

    class Meta:
        db_table = "Customers"
        
        
        
class Company(models.Model):
    name = models.CharField(max_length=100)
    gst = models.CharField(max_length=20)
    address = models.CharField(max_length=500, null=True)
    zip = models.IntegerField()
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    phone = models.CharField(max_length=10)
    email = models.EmailField(max_length=100)
    web_site = models.URLField(null=True)
    prefix = models.CharField(max_length=5, unique=True, help_text="Unique prefix for invoice numbers")

    def __str__(self):
        return self.name
    
    
class ParcalService(models.Model):
    name = models.CharField(max_length=100)
    label = models.CharField(max_length=100)
    
    class Meta :
        db_table = 'parcal_service'
        
    def __str__(self):
        return self.name



class Shipping(models.Model):
    created_user = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=500)
    zipcode = models.CharField(max_length=300,null=True)
    city = models.CharField(max_length=100)
    state = models.ForeignKey(State,on_delete=models.CASCADE,null=True)
    country = models.CharField(max_length=100)
    phone = models.CharField(max_length=100)
    email = models.CharField(max_length=100, null=True, blank=True)

    class Meta :
        db_table = "Shipping_Address"

    def __str__(self):
        return self.name

import uuid

class Products(models.Model):
    PRODUCT_TYPES = [
        ('single', 'Single'),
        ('variant', 'Variant'),
    ]
    
    UNIT_TYPES = [
        ('BOX', 'BOX'),
        ('NOS', 'NOS'),
        ('PRS', 'PRS'),
        ('SET', 'SET'),
        ('SET OF 12', 'SET OF 12'),
        ('SET OF 16', 'SET OF 16'),
        ('SET OF 6', 'SET OF 6'),
        ('SET OF 8', 'SET OF 8'),
    ]
    PURCHASE_TYPES=[
        ('Local', 'Local'),
        ('International', 'International'),
    ]
    STATUS_TYPES=[
        ('Approved','Approved'),
        ('Disapproved','Disapproved')
    ]
    
    
    created_user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    warehouse = models.ForeignKey(WareHouse,on_delete=models.CASCADE,null=True,blank=True,related_name="products")
    product_approved_user=models.ForeignKey(User,on_delete=models.CASCADE,null=True, related_name='approved_products')
    name = models.CharField(max_length=500)
    hsn_code = models.CharField(max_length=100)
    family = models.ManyToManyField(Family, related_name='familys')
    type = models.CharField(max_length=100, choices=PRODUCT_TYPES, default='single')
    unit = models.CharField(max_length=100, choices=UNIT_TYPES, default="BOX")
    purchase_rate = models.FloatField()
    tax = models.FloatField() 
    image = models.ImageField(upload_to='images/', null=True)
    exclude_price = models.FloatField(editable=False,default=0.0) 
    selling_price=models.FloatField(default=0.0,null=True)
    landing_cost=models.FloatField(null=True)
    retail_price=models.FloatField(null=True)
    stock = models.IntegerField(default=0)
    locked_stock = models.IntegerField(default=0)
    color = models.CharField(max_length=100, null=True, blank=True)
    size = models.CharField(max_length=100, null=True, blank=True)
    groupID = models.CharField(max_length=100, null=True, blank=True)
    variantID = models.CharField(max_length=100, unique=True, null=True, blank=True)
    purchase_type=models.CharField(max_length=100,choices=PURCHASE_TYPES,default='International')
    approval_status=models.CharField(max_length=100,choices=STATUS_TYPES,default='Disapproved')
    duty_charge=models.FloatField(null=True, blank=True, default=0.0)
    product_category = models.ForeignKey(ProductCategoryModel, on_delete=models.SET_NULL, null=True, blank=True, related_name='products')
    rack_details = models.JSONField(default=list, blank=True, null=True)
    damaged_stock = models.IntegerField(default=0, null=True, blank=True)
    partially_damaged_stock = models.IntegerField(default=0, null=True, blank=True)
    

    def generate_variant_id(self):
        """Generates a unique variantID using UUID"""
        return str(uuid.uuid4())
    
    def save(self, *args, **kwargs):
        if self.selling_price is None:
            self.selling_price = 0.0
       
        # Generate variantID if not already set
       
        if not self.variantID:
            self.variantID = self.generate_variant_id()
            
        # rack stock calculation for usable, damaged, and partially damaged
        usable = 0
        damaged = 0
        partial = 0
        for rack in self.rack_details or []:
            usability = rack.get('usability')
            qty = rack.get('rack_stock', 0)
            if usability == 'usable':
                usable += qty
            elif usability == 'damaged':
                damaged += qty
            elif usability == 'partially_damaged':
                partial += qty
        self.stock = usable
        self.damaged_stock = damaged
        self.partially_damaged_stock = partial
        super().save(*args, **kwargs) 
     

    def lock_stock(self, quantity):
        """Locks stock without reducing actual stock"""
        if quantity > (self.stock - self.locked_stock):  
            raise ValueError("Not enough available stock to lock.")
        self.locked_stock += quantity
        self.save()

    def release_lock(self, quantity):
        """Releases locked stock (if order is canceled or modified)"""
        if self.locked_stock >= quantity:
            self.locked_stock -= quantity
            self.save()

    def reduce_stock(self, quantity):
        """Reduces stock after order is shipped"""
        if self.stock >= quantity and self.locked_stock >= quantity:
            self.stock -= quantity
            self.locked_stock -= quantity
            self.save()
        else:
            raise ValueError("Not enough stock to fulfill order.")   


    def __str__(self):
        return self.name
    
    class Meta:
        db_table = "Products"



class SingleProducts(models.Model):
    created_user = models.ForeignKey(User,on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='images/')

    class Meta:
        db_table = "single_product"

    def __str__(self):
        return f"{self.product.name}"
class VariantProducts(models.Model):
    created_user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='variant_products')
    name = models.CharField(max_length=500)
    stock = models.PositiveBigIntegerField(default=0, null=True)
    color = models.CharField(max_length=100, null=True, blank=True)
    is_variant = models.BooleanField(default=False)

    class Meta:
        db_table = "variant_product"   

class VariantImages(models.Model):
    variant_product = models.ForeignKey(VariantProducts, on_delete=models.CASCADE, related_name='variant_images')
    image = models.ImageField(upload_to='images/')
    class Meta:
        db_table = "variant_images"
        
    def __str__(self):
        return f"{self.variant_product.name} - {self.image}"         

class ProductAttributeVariant(models.Model):
    variant_product = models.ForeignKey(VariantProducts, on_delete=models.CASCADE,related_name="sizes")
    attribute = models.CharField(max_length=100)
    stock = models.PositiveBigIntegerField(default=0)

    class Meta:
        db_table = "product_attribute_variant"

    def __str__(self):
        return f"{self.variant_product.name} - {self.attribute}"    
    


    
class Bank(models.Model):
    created_user = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    name = models.CharField(max_length=100)
    account_number = models.CharField(max_length=100)
    ifsc_code = models.CharField(max_length=100)
    branch = models.CharField(max_length=100)
    open_balance = models.FloatField()
    created_at = models.DateField(null=True, blank=True)
    class Meta:
        db_table = "Bank"
        
    def  __str__(self):
        return self.name


class InternalTransfer(models.Model):
    sender_bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='sent_transfers')
    receiver_bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='received_transfers')
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    transactionID = models.CharField(max_length=50, null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True)

    class Meta:
        db_table = "internal_transfer"

    def __str__(self):
        return f"Transfer of {self.amount} from {self.sender_bank} to {self.receiver_bank}"



class Order(models.Model):
    manage_staff = models.ForeignKey(User, on_delete=models.CASCADE)
    warehouses = models.ForeignKey(WareHouse, on_delete=models.CASCADE, null=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="companies", null=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="customer")
    invoice = models.CharField(max_length=20, unique=True, blank=True)
    billing_address = models.ForeignKey(Shipping, on_delete=models.CASCADE, related_name="billing_address", default="")
    order_date = models.CharField(max_length=100)
    family = models.ForeignKey(Family, on_delete=models.CASCADE)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    code_charge = models.IntegerField(default=0, null=True)
    shipping_mode = models.CharField(max_length=100, null=True,blank=True)
    shipping_charge = models.IntegerField(default=0, null=True)

    locked_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='locked_orders')
    locked_at = models.DateTimeField(null=True, blank=True)
    cod_amount = models.FloatField(default=0.0, null=True, blank=True)  # New field for COD amount

    payment_status = models.CharField(max_length=20, choices=[
        ('paid', 'paid'),
        ('COD', 'COD'),
        ('credit', 'credit'),
        ('PENDING', 'PENDING'),
        ('VOIDED', 'VOIDED')
    ], default='paid')

    status = models.CharField(max_length=100, choices=[
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Shipped', 'Shipped'),
        ('Invoice Created', 'Invoice Created'),
        ('Invoice Approved', 'Invoice Approved'),
        ('Waiting For Confirmation', 'Waiting For Confirmation'),
        ('To Print', 'To Print'),
        ('Invoice Rejected', 'Invoice Rejected'),
        ('Order Request by Warehouse', 'Order Request by Warehouse'),
        ('Processing', 'Processing'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
        ('Refunded', 'Refunded'),
        ('Rejected', 'Rejected'),
        ('Return', 'Return'),
        ('Packing under progress', 'Packing under progress'),
        ('Packed', 'Packed'),
        ('Ready to ship', 'Ready to ship'),
    ], default='pending')

    total_amount = models.FloatField()
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name="bank")
    note = models.TextField(default="")
    accounts_note = models.TextField(default="", blank=True, null=True)

    payment_method = models.CharField(max_length=50, choices=[
        ('Credit Card', 'Credit Card'),
        ('Debit Card', 'Debit Card'),
        ('PayPal', 'PayPal'),
        ('1 Razorpay', '1 Razorpay'),
        ('Net Banking', 'Net Banking'),
        ('Bank Transfer', 'Bank Transfer'),
        ('Cash on Delivery (COD)', 'Cash on Delivery (COD)'),
    ], default='Net Banking')

    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.invoice:
            self.invoice = self.generate_invoice_number()

        # if self.pk:  # Check if the object already exists
        #     original = Order.objects.get(pk=self.pk)
        #     if original.status != self.status:
        #         self.updated_at = now()
        if self.pk:  # If updating an existing order
            previous_status = Order.objects.filter(pk=self.pk).values_list("status", flat=True).first()

            if previous_status and previous_status != self.status:
                # If order is shipped, reduce stock
                if self.status == 'Shipped':
                    for item in self.items.all():
                        product = item.product
                        if product.locked_stock >= item.quantity:
                            product.locked_stock -= item.quantity  # Unlock stock
                            product.stock -= item.quantity  # Reduce actual stock
                            product.save()
                        else:
                            raise ValueError("Locked stock inconsistency detected!")


        super().save(*args, **kwargs)

    def generate_invoice_number(self):
        if not self.company:
            raise ValueError("Company must be set to generate an invoice number.")

        prefix = self.company.prefix  # Retrieve prefix from the associated Company
        number = self.get_next_invoice_number(prefix)
        invoice_number = f"{prefix}{number}"
        return invoice_number

    def get_next_invoice_number(self, prefix):
        highest_invoice = Order.objects.filter(invoice__startswith=prefix).order_by('invoice').last()

        if highest_invoice:
            last_number = highest_invoice.invoice[len(prefix):]  # Remove the prefix
            try:
                number = int(last_number) + 1
            except ValueError:
                number = 1
        else:
            number = 1  # If no previous invoice exists, start with 1

        return str(number).zfill(6)  # Zero-pad to 6 digits (FPN000001, FPN000002, etc.)

     

    def __str__(self):
        return f"Order {self.invoice} by {self.customer}"


class OrderImage(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='order_images')
    image = models.ImageField(upload_to='order_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for Order {self.order.invoice} - {self.id}"

    class Meta:
        db_table = "order_images"
        

class OrderPaymentImages(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='payment_images')
    image = models.ImageField(upload_to='payment_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Payment Image for Order {self.order.invoice} - {self.id}"
    
    class Meta:
        db_table = "order_payment_images"
    

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    size = models.ForeignKey(ProductAttributeVariant, on_delete=models.CASCADE,null=True)
    variant = models.ForeignKey(VariantProducts, on_delete=models.CASCADE,null=True)
    description = models.CharField(max_length=100,null=True)
    rate = models.DecimalField(max_digits=10, decimal_places=2)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0, null=True)
    tax = models.PositiveIntegerField()  # tax percentage
    quantity = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.product.name} (x{self.quantity})"
    
    def save(self, *args, **kwargs):
        product = self.product

        if self.pk:  # If updating an existing order item
            original_quantity = OrderItem.objects.get(pk=self.pk).quantity  # Get original quantity
            
            if self.quantity != original_quantity:  # If quantity has changed
                change_in_quantity = self.quantity - original_quantity  # Difference
                
                # Check if additional stock is available for locking
                if change_in_quantity > 0:  
                    available_stock = product.stock - product.locked_stock
                    if change_in_quantity > available_stock:
                        raise ValueError("Not enough available stock to lock additional quantity.")
                    product.locked_stock += change_in_quantity  # Lock additional stock

                # If quantity is reduced, release stock
                elif change_in_quantity < 0:  
                    product.locked_stock += change_in_quantity  # Reduce locked stock

        else:  # New order item being created
            available_stock = product.stock - product.locked_stock
            if self.quantity > available_stock:
                raise ValueError("Not enough available stock to lock.")
            product.locked_stock += self.quantity  # Lock stock

        product.save()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Release locked stock if the order item is deleted"""
        product = self.product

        if product.locked_stock >= self.quantity:  # Ensure locked stock is sufficient
            product.locked_stock -= self.quantity  # Unlock the stock
            product.save()

        super().delete(*args, **kwargs)

        
        
class BeposoftCart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE,related_name='products')
    quantity = models.PositiveIntegerField(default=1)
    discount = models.IntegerField(null=True, blank=True)
    note = models.TextField(blank=True, null=True)
    price = models.FloatField(null=True, blank=True) 
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.product.name} - {self.quantity}" 
    
    class Meta:
        db_table = "beposoft_cart"
        
class AdvanceReceipt(models.Model):
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, null=True, related_name='advance_receipts')
    payment_receipt = models.CharField(max_length=15, unique=True, editable=False)  # Auto-generated ID
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='advance_receipts')
    transactionID = models.CharField(max_length=50)
    received_at = models.DateField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    remark = models.TextField()

    def save(self, *args, **kwargs):
        if not self.payment_receipt:
            last_id = AdvanceReceipt.objects.all().order_by('id').last()
            next_id = last_id.id + 1 if last_id else 1
            self.payment_receipt = f"ADV-{str(next_id).zfill(4)}{chr(65 + (next_id % 26))}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Advance Receipt #{self.payment_receipt} for Customer: {self.customer}"

    class Meta:
        db_table = "advance_receipts"
        
class BankReceipt(models.Model):
    payment_receipt = models.CharField(max_length=15, unique=True, editable=False)  # Auto-generated ID
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='bank_receipts')
    transactionID = models.CharField(max_length=50)
    received_at = models.DateField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    remark = models.TextField()

    def save(self, *args, **kwargs):
        if not self.payment_receipt:
            last_id = BankReceipt.objects.all().order_by('id').last()
            next_id = last_id.id + 1 if last_id else 1
            self.payment_receipt = f"ADV-{str(next_id).zfill(4)}{chr(65 + (next_id % 26))}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Bank Receipt #{self.payment_receipt}"

    class Meta:
        db_table = "bank_receipts"

    
class PaymentReceipt(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='recived_payment')
    customer = models.ForeignKey(Customers,on_delete=models.CASCADE,null=True)
    payment_receipt = models.CharField(max_length=10, unique=True, editable=False)  # Combined ID
    amount = models.CharField(max_length=100)
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE,related_name='payments')
    transactionID = models.CharField(max_length=50)
    received_at = models.DateField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    remark = models.TextField()

    def save(self, *args, **kwargs):
        # Generate a unique payment_receipt if not set
        if not self.payment_receipt:
            # Get the last receipt ID and increment
            last_id = PaymentReceipt.objects.all().order_by('id').last()
            next_id = last_id.id + 1 if last_id else 1
            # Create formatted ID, e.g., REC-0001A
            self.payment_receipt = f"REC-{str(next_id).zfill(4)}{chr(65 + (next_id % 26))}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Receipt #{self.payment_receipt} for Order: {self.order.invoice}"

    class Meta:
        db_table = "receipts"
        
    

class PerfomaInvoiceOrder(models.Model):
    manage_staff = models.ForeignKey(User, on_delete=models.CASCADE)
    warehouses_obj = models.ForeignKey(WareHouse, on_delete=models.CASCADE, null=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="perfoma_companies", null=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="perfoma_customer")
    invoice = models.CharField(max_length=20, unique=True, blank=True)
    billing_address = models.ForeignKey(Shipping, on_delete=models.CASCADE, related_name="perfoma_billing_address")
    order_date = models.CharField(max_length=100)
    family = models.ForeignKey(Family, on_delete=models.CASCADE)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    code_charge = models.IntegerField(default=0, null=True)
    shipping_mode = models.CharField(max_length=100, null=True)
    shipping_charge = models.IntegerField(default=0, null=True)
    status = models.CharField(max_length=100, choices=[
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Shipped', 'Shipped'),
        ('Invoice Created', 'Invoice Created'),
        ('Invoice Approved', 'Invoice Approved'),
        ('Waiting For Confirmation', 'Waiting For Confirmation'),
        ('To Print', 'To Print'),
        ('Invoice Rejected', 'Invoice Rejected'),
        ('Processing', 'Processing'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
        ('Refunded', 'Refunded'),
        ('Return', 'Return'),
    ], default='Pending')
    total_amount = models.FloatField()
    note = models.TextField(null=True)
    
    def save(self, *args, **kwargs):
        if not self.invoice:
            self.invoice = self.generate_invoice_number()
            print(f"Generated invoice number: {self.invoice}")
        super().save(*args, **kwargs)

    def generate_invoice_number(self):
        if not self.company:
            raise ValueError("Company must be set to generate an invoice number.")
        
        prefix = self.company.prefix  # Retrieve prefix from the associated Company
        number = self.get_next_invoice_number(prefix)
        invoice_number = f"{prefix}{number}"
        return invoice_number

    def get_next_invoice_number(self, prefix):
        highest_invoice = PerfomaInvoiceOrder.objects.filter(invoice__startswith=prefix).order_by('invoice').last()
        
        if highest_invoice:
            last_number = highest_invoice.invoice[len(prefix):]  # Remove the prefix
            try:
                number = int(last_number) + 1 
            except ValueError:
                number = 1  
        else:
            number = 1  # If no previous invoice exists, start with 1
        
        return str(number).zfill(6)  # Zero-pad to 6 digits

    def __str__(self):
        return f"Perfoma Invoice {self.invoice} by {self.customer}"    


class PerfomaInvoiceOrderItem(models.Model):
    order = models.ForeignKey(PerfomaInvoiceOrder, on_delete=models.CASCADE, related_name='perfoma_items')
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    
    description = models.CharField(max_length=100,null=True)
    rate = models.IntegerField()  # without GST
    tax = models.PositiveIntegerField()  # tax percentage
    discount = models.IntegerField(default=0, null=True)
    quantity = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.product.name} (x{self.quantity})"




class Warehousedata(models.Model):
    MESSAGE_CHOICES=[
        ('pending','pending'),
        ('sent','sent')
    ]
    order=models.ForeignKey(Order,on_delete=models.CASCADE,related_name='warehouse')
    box=models.CharField(max_length=100, default="")
    weight=models.CharField(max_length=30, default="")
    length=models.CharField(max_length=30, default="")
    breadth=models.CharField(max_length=30, default="")
    height=models.CharField(max_length=30,null=True)
    image=models.ImageField(upload_to='images/',null=True,blank=True)
    image_before=models.ImageField(upload_to='images/',null=True,blank=True)
    packed_by=models.ForeignKey(User,on_delete=models.CASCADE, default="")
    verified_by=models.ForeignKey(User,on_delete=models.CASCADE,null=True,related_name='verified_user')
    checked_by=models.ForeignKey(User,on_delete=models.CASCADE,null=True,related_name='checked_user')
    parcel_service=models.ForeignKey(ParcalService, on_delete=models.CASCADE,null=True, blank=True)  
    tracking_id=models.CharField(max_length=100,null=True, blank=True)
    actual_weight = models.DecimalField(max_digits=10,decimal_places=2, null=True, blank=True,default=0.0)
    parcel_amount=models.DecimalField(max_digits=10,decimal_places=2, null=True, blank=True,default=0.0)
    shipping_charge=models.DecimalField(max_digits=10, decimal_places=2,null=True, blank=True)
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE,null=True)
    status=models.CharField(max_length=30,null=True, blank=True)
    shipped_date=models.DateField(null=True, blank=True)
    postoffice_date=models.DateField(null=True,blank=True)
    message_status=models.CharField(max_length=30,choices=MESSAGE_CHOICES,default="pending")
    def __str__(self):
        parcel_service_name = self.parcel_service.name if self.parcel_service else "No Parcel Service"
        shipped_date_str = self.shipped_date.strftime("%Y-%m-%d") if self.shipped_date else "No Shipped Date"
        return f"{self.box} - {parcel_service_name} ({shipped_date_str})"


class GRVModel(models.Model):
    STATUS_CHOICES=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('Waiting For Approval', 'Waiting For Approval'),
    ]
    REMARK_CHOICES=[
        ('return','Return'),
        ('refund','Refund'),
        ('exchange','Exchange'),
    ]
    REASON_CHOICES=[
        ('damaged', 'damaged'),
        ('partially_damaged','partially_damaged'),
        ('usable','usable'),
    ]
    order=models.ForeignKey(Order,on_delete=models.CASCADE)
    product=models.CharField(max_length=100)
    returnreason=models.CharField(max_length=200, choices=REASON_CHOICES, default='usable')
    price=models.DecimalField(max_digits=10, decimal_places=2)
    quantity=models.IntegerField()
    remark=models.CharField(max_length=20,choices=REMARK_CHOICES,null=True)
    status=models.CharField(max_length=30,choices=STATUS_CHOICES,default='Waiting For Approval',null=True)
    date=models.DateField(null=True)
    time=models.TimeField(null=True)
    note=models.TextField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    product_id = models.ForeignKey(Products, on_delete=models.CASCADE, null=True, blank=True)

    def update_status(self, new_status):
        """112
        Updates the status and sets the updated_at field to the current time.
        """
        if self.status != new_status: 
            self.status = new_status
            self.updated_at = datetime.now() 
            print(f"Status updated to '{new_status}' on {self.updated_at}")
            self.save()  
        else:
            print("No change in status.")


class OrderRequest(models.Model):
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="order_requests")
    source_warehouse = models.ForeignKey(WareHouse, on_delete=models.CASCADE, related_name="source_requests")
    target_warehouse = models.ForeignKey(WareHouse, on_delete=models.CASCADE, related_name="target_requests")
    quantity = models.PositiveIntegerField()
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('approved', 'Approved'), ('declined', 'Declined')], default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)   

    
class Attendance(models.Model):
    ATTENDANCE_STATUS = [
        ('Present', 'Present'),
        ('Absent', 'Absent'),
        ('Half Day Leave', 'Half Day Leave')
       
    ]

    staff = models.ForeignKey('User', on_delete=models.CASCADE, related_name="attendance_records")
    date = models.DateField()
    attendance_status= models.CharField(max_length=20, choices=ATTENDANCE_STATUS,default='Present')

    def __str__(self):
        return f"{self.staff.name} - {self.date} - {self.attendance_status}"



    
