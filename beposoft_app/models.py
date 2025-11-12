from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from .validators import validate_gst
import re
from django.core.exceptions import ValidationError
from decimal import Decimal
import random
from django.utils.timezone import now 
from datetime import datetime
from django.db import transaction
# from beposoft_app.utils.racks import allocate_racks_for_quantity, RackAllocationError


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
    

class Districts(models.Model):
    name = models.CharField(max_length=50, null=True, blank=True)
    state = models.ForeignKey(State, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = "Districts"

    def __str__(self):
        return self.name
    

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


class CustomerType(models.Model):
    type_name = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.type_name


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
    family = models.ForeignKey(Family, on_delete=models.SET_NULL, null=True, blank=True) 
    customer_type = models.ForeignKey(CustomerType, on_delete=models.SET_NULL, null=True, blank=True)
    gst_confirm = models.CharField(max_length=50, null=True, blank=True)

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
    alt_phone = models.CharField(max_length=100, null=True, blank=True)
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
    
    def _recompute_stock_fields(self):
        usable = damaged = partial = 0
        for rack in self.rack_details or []:
            qty = int(rack.get('rack_stock', 0) or 0)
            u = rack.get('usability')
            if u == 'usable':
                usable += qty
            elif u == 'damaged':
                damaged += qty
            elif u == 'partially_damaged':
                partial += qty
        self.stock = usable
        self.damaged_stock = damaged
        self.partially_damaged_stock = partial
        return {"stock", "damaged_stock", "partially_damaged_stock"}

    def save(self, *args, **kwargs):
        # Default selling_price
        if self.selling_price is None:
            self.selling_price = 0.0

        # Ensure variantID
        if not self.variantID:
            self.variantID = self.generate_variant_id()

        # Always recompute before saving
        computed_fields = self._recompute_stock_fields()

        # If caller uses update_fields, make sure computed fields are included
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            # normalize to a set
            uf = set(update_fields)
            # if rack_details is being updated, we must also update computed fields
            if "rack_details" in uf:
                uf |= computed_fields
            # If we're saving for any reason, we can safely include computed fields
            # (comment previous line and use next line instead if you want them always)
            # uf |= computed_fields
            kwargs["update_fields"] = list(uf)

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


def reduce_product_rack_stock_on_ship(order):
    """
    Reduce rack_stock and rack_lock in product.rack_details for each OrderItem in the order.
    Call this after order status is set to 'Shipped'.
    """
    for item in order.items.all():
        product = item.product
        changed = False
        for order_rack in item.rack_details or []:
            for prod_rack in product.rack_details or []:
                if (
                    prod_rack.get("rack_id") == order_rack.get("rack_id")
                    and prod_rack.get("column_name") == order_rack.get("column_name")
                ):
                    qty = int(order_rack.get("quantity", 0))
                    prod_rack["rack_stock"] = max(0, int(prod_rack.get("rack_stock", 0)) - qty)
                    prod_rack["rack_lock"] = max(0, int(prod_rack.get("rack_lock", 0)) - qty)
                    changed = True
        if changed:
            product.save(update_fields=["rack_details"])


def release_product_rack_lock_on_invoice_reject(order):
    """
    For each OrderItem in the order, reduce the rack_lock in product.rack_details
    by the quantity in the item's rack_details.
    Call this when order status is set to 'Invoice Rejected'.
    """
    for item in order.items.all():
        product = item.product
        changed = False
        for order_rack in item.rack_details or []:
            for prod_rack in product.rack_details or []:
                if (
                    prod_rack.get("rack_id") == order_rack.get("rack_id")
                    and prod_rack.get("column_name") == order_rack.get("column_name")
                ):
                    qty = int(order_rack.get("quantity", 0))
                    prod_rack["rack_lock"] = max(0, int(prod_rack.get("rack_lock", 0)) - qty)
                    changed = True
        if changed:
            product.save(update_fields=["rack_details"])


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
    confirmed_by = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='confirmed_orders', null=True, blank=True)

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

    # def save(self, *args, **kwargs):
    #     if not self.invoice:
    #         self.invoice = self.generate_invoice_number()

       
    #     if self.pk: 
    #         previous_status = Order.objects.filter(pk=self.pk).values_list("status", flat=True).first()

    #         if previous_status and previous_status != self.status:
               
    #             if self.status == 'Shipped':
    #                 reduce_product_rack_stock_on_ship(self)
    #                 for item in self.items.all():
    #                     product = item.product
    #                     if product.locked_stock >= item.quantity:
    #                         product.locked_stock -= item.quantity 
    #                         product.stock -= item.quantity  
    #                         product.save()
    #                     else:
    #                         raise ValueError("Locked stock inconsistency detected!")
    #             elif self.status == 'Invoice Rejected':
    #                 release_product_rack_lock_on_invoice_reject(self)
            
    #     super().save(*args, **kwargs)
    
    def save(self, *args, **kwargs):
        if not self.invoice:
            self.invoice = self.generate_invoice_number()

        if self.pk:
            previous_status = Order.objects.filter(pk=self.pk).values_list("status", flat=True).first()

            if previous_status and previous_status != self.status:
                # Lock related products to avoid races while we mutate rack_details
                items_qs = self.items.select_related("product").all()
                product_ids = list(items_qs.values_list("product_id", flat=True))
                products_map = {
                    p.pk: p for p in Products.objects.select_for_update().filter(pk__in=product_ids)
                }

                if self.status == 'Shipped':
                    # 1) Move qty from rack_stock -> shipped and drop rack_lock (per rack)
                    reduce_product_rack_stock_on_ship(self)  # this calls product.save(update_fields=["rack_details"])
                    # 2) Only unlock the global locked_stock counter
                    for item in items_qs:
                        product = products_map[item.product_id]
                        if product.locked_stock >= item.quantity:
                            product.locked_stock -= item.quantity
                            product.save(update_fields=["locked_stock"])
                        else:
                            raise ValueError("Locked stock inconsistency detected!")

                elif self.status == 'Invoice Rejected':
                    # 1) Release rack locks (JSON)
                    release_product_rack_lock_on_invoice_reject(self)
                    # 2) Release the global locked_stock counter
                    for item in items_qs:
                        product = products_map[item.product_id]
                        product.locked_stock = max(0, (product.locked_stock or 0) - item.quantity)
                        product.save(update_fields=["locked_stock"])

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


class WarehouseOrder(models.Model):
    manage_staff = models.ForeignKey(User, on_delete=models.CASCADE, related_name="warehouse_orders")
    warehouses = models.ForeignKey(WareHouse, on_delete=models.CASCADE, null=True, blank=True, related_name="requesting_warehouse")
    receiiver_warehouse = models.ForeignKey(WareHouse, on_delete=models.CASCADE, related_name="receiver_warehouse", null=True, blank=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="warehouse_companies", null=True)
    invoice = models.CharField(max_length=20, unique=True, blank=True)
    billing_address = models.ForeignKey(Shipping, on_delete=models.CASCADE, related_name="warehouse_billing_address", null=True, blank=True)
    order_date = models.CharField(max_length=100)
    shipping_charge = models.IntegerField(default=0, null=True, blank=True)

    status = models.CharField(max_length=100, choices=[
        ('Created', 'Created'),
        ('Approved', 'Approved'),
        ('Completed', 'Completed'),
        ('Received', 'Received'),
        ('Rejected', 'Rejected'),
        ('Cancelled', 'Cancelled'),
    ], default='Created')

    note = models.TextField(default="", blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "warehouse_order"

    def __str__(self):
        return f"WarehouseOrder {self.invoice} for {self.warehouses} by {self.manage_staff}"

    def generate_invoice_number(self):
        """
        Separate series from regular orders. Example: 'WH' + Company prefix + 6-digit counter.
        """
        if not self.company:
            raise ValueError("Company must be set to generate a warehouse invoice number.")
        prefix = f"WH{self.company.prefix}"
        highest = WarehouseOrder.objects.filter(invoice__startswith=prefix).order_by('invoice').last()
        if highest:
            last_num = highest.invoice[len(prefix):]
            try:
                num = int(last_num) + 1
            except ValueError:
                num = 1
        else:
            num = 1
        return f"{prefix}{str(num).zfill(6)}"

    # def save(self, *args, **kwargs):
    #     if not self.invoice:
    #         self.invoice = self.generate_invoice_number()
    #     super().save(*args, **kwargs)

    def save(self, *args, **kwargs):
        is_update = self.pk is not None
        old_status = None

        if is_update:
            old_status = WarehouseOrder.objects.filter(pk=self.pk)\
                                            .values_list("status", flat=True)\
                                            .first()

        if not self.invoice:
            self.invoice = self.generate_invoice_number()

        super().save(*args, **kwargs)

        if is_update and old_status != self.status:
            if self.status == "Completed":
                reduce_rack_stock_for_warehouse_order(self)
            elif self.status in ["Rejected", "Cancelled"]:
                release_rack_lock_for_warehouse_order(self)



class WarehouseOrderItem(models.Model):
    order = models.ForeignKey(WarehouseOrder, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    size = models.ForeignKey(ProductAttributeVariant, on_delete=models.CASCADE, null=True, blank=True)
    variant = models.ForeignKey(VariantProducts, on_delete=models.CASCADE, null=True, blank=True)
    description = models.CharField(max_length=100, null=True, blank=True)
    quantity = models.PositiveIntegerField()
    rack_details = models.JSONField(default=list, blank=True, null=True)

    class Meta:
        db_table = "warehouse_order_item"

    def __str__(self):
        return f"{self.product.name} (x{self.quantity}) [WH]"


def reduce_rack_stock_for_warehouse_order(order):
    """
    For each item in the WarehouseOrder, subtract its rack_details quantities
    from the corresponding rack_stock and rack_lock in Products.rack_details.
    """
    for item in order.items.select_related("product").all():
        product = item.product
        changed = False

        # Ensure we lock the product row for safe concurrent updates
        with transaction.atomic():
            product = Products.objects.select_for_update().get(pk=product.pk)
            prod_racks = product.rack_details or []

            # Build quick lookup by (rack_id, column_name)
            index = {
                (r.get("rack_id"), r.get("column_name")): r for r in prod_racks
            }

            for rack in item.rack_details or []:
                key = (rack.get("rack_id"), rack.get("column_name"))
                target = index.get(key)
                if not target:
                    continue
                qty = int(rack.get("quantity", 0) or 0)

                # subtract quantity from rack_stock and rack_lock
                target["rack_stock"] = max(0, int(target.get("rack_stock", 0)) - qty)
                target["rack_lock"] = max(0, int(target.get("rack_lock", 0)) - qty)
                changed = True

            if changed:
                product.rack_details = prod_racks
                product.save(update_fields=["rack_details"])

def release_rack_lock_for_warehouse_order(order):
    """
    When a WarehouseOrder is Rejected or Cancelled, release the locked stock
    (rack_lock) for each rack in every item without touching the actual
    rack_stock.
    """
    for item in order.items.select_related("product").all():
        product = item.product
        changed = False

        # Lock the product row to avoid race conditions
        with transaction.atomic():
            product = Products.objects.select_for_update().get(pk=product.pk)
            prod_racks = product.rack_details or []

            # Quick lookup by (rack_id, column_name)
            index = {
                (r.get("rack_id"), r.get("column_name")): r for r in prod_racks
            }

            for rack in item.rack_details or []:
                key = (rack.get("rack_id"), rack.get("column_name"))
                target = index.get(key)
                if not target:
                    continue

                qty = int(rack.get("quantity", 0) or 0)

                # Only subtract from rack_lock, never below 0
                target["rack_lock"] = max(0, int(target.get("rack_lock", 0)) - qty)
                changed = True

            if changed:
                product.rack_details = prod_racks
                product.save(update_fields=["rack_details"])


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
    

def _auto_allocate_racks(product, quantity: int, release_allocations=None):
    if quantity <= 0:
        return []
    locked_product = Products.objects.select_for_update().get(pk=product.pk)
    return allocate_racks_for_quantity(
        locked_product,
        int(quantity),
        release_allocations=release_allocations or [],
    )


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
    rack_details = models.JSONField(default=list, blank=True, null=True)
    

    def __str__(self):
        return f"{self.product.name} (x{self.quantity})"
    
    

    
    def save(self, *args, **kwargs):
        product = self.product

        if self.pk: 
            original_quantity = OrderItem.objects.get(pk=self.pk).quantity 
            
            if self.quantity != original_quantity: 
                change_in_quantity = self.quantity - original_quantity 
                
               
                if change_in_quantity > 0:  
                    available_stock = product.stock - product.locked_stock
                    if change_in_quantity > available_stock:
                        raise ValueError("Not enough available stock to lock additional quantity.")
                    product.locked_stock += change_in_quantity 

                elif change_in_quantity < 0:  
                    product.locked_stock += change_in_quantity 

        else: 
            available_stock = product.stock - product.locked_stock
            if self.quantity > available_stock:
                raise ValueError("Not enough available stock to lock.")
            product.locked_stock += self.quantity 

        product.save()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Release locked stock if the order item is deleted"""
        product = self.product

        if product.locked_stock >= self.quantity:
            product.locked_stock -= self.quantity
            product.save()

        super().delete(*args, **kwargs)
        

from django.db.models.signals import pre_save, post_delete
from django.dispatch import receiver
def update_product_rack_lock(product, rack_details, diff=1):
    """
    Update the rack_lock in product.rack_details based on rack_details.
    diff: +1 to lock, -1 to unlock
    """
    product_racks = product.rack_details or []
    changed = False

    for order_rack in rack_details or []:
        for prod_rack in product_racks:
            if (
                prod_rack.get("rack_id") == order_rack.get("rack_id")
                and prod_rack.get("column_name") == order_rack.get("column_name")
            ):
                prod_rack["rack_lock"] = int(prod_rack.get("rack_lock", 0)) + diff * int(order_rack.get("quantity", 0))
                if prod_rack["rack_lock"] < 0:
                    prod_rack["rack_lock"] = 0
                changed = True
    if changed:
        product.rack_details = product_racks
        product.save(update_fields=["rack_details"])

# @receiver(pre_save, sender=OrderItem)
# def handle_orderitem_rack_lock(sender, instance, **kwargs):
#     if instance.pk:
#         old = OrderItem.objects.get(pk=instance.pk)
#         # Remove old rack locks
#         update_product_rack_lock(old.product, old.rack_details, diff=-1)
#     # Add new rack locks
#     update_product_rack_lock(instance.product, instance.rack_details, diff=1)
def _as_int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0

def _qty_from_row(row):
    # Accepts 'quantity' (preferred) but tolerates 'qty' or 'rack_lock' if your client sends those.
    return _as_int(row.get('quantity') or row.get('qty') or row.get('rack_lock'))

@receiver(pre_save, sender=OrderItem)
def handle_orderitem_rack_lock(sender, instance, **kwargs):
    """
    Replace-style updates for rack locks:
    - Compute per-rack delta = new_qty - old_qty
    - Apply deltas to product.rack_details[*].rack_lock
    - Validates only the positive deltas against available stock
    - Works even if the OrderItem product changes
    """
    old_alloc = {}
    old_product_id = None

    if instance.pk:
        old = OrderItem.objects.only('rack_details', 'product_id').get(pk=instance.pk)
        old_product_id = old.product_id
        for r in (old.rack_details or []):
            key = (r.get('rack_id'), r.get('column_name'))
            old_alloc[key] = _qty_from_row(r)

    new_alloc = {}
    for r in (instance.rack_details or []):
        key = (r.get('rack_id'), r.get('column_name'))
        new_alloc[key] = _qty_from_row(r)

    # Build deltas (new - old)
    all_keys = set(old_alloc) | set(new_alloc)
    deltas = {k: new_alloc.get(k, 0) - old_alloc.get(k, 0) for k in all_keys}

    def apply_deltas_to_product(product_id, deltas_map):
        if not product_id:
            return
        with transaction.atomic():
            product = Products.objects.select_for_update().get(pk=product_id)
            product_racks = product.rack_details or []
            index = {(pr.get("rack_id"), pr.get("column_name")): pr for pr in product_racks}

            # validate positive deltas
            for key, d in deltas_map.items():
                if d <= 0:
                    continue
                pr = index.get(key)
                if not pr:
                    raise ValueError(f"Rack not found for key={key}")
                rack_stock = _as_int(pr.get("rack_stock"))
                rack_lock = _as_int(pr.get("rack_lock"))
                available = max(0, rack_stock - rack_lock)
                if d > available:
                    raise ValueError(f"Not enough available in rack {key}: need {d}, available {available}")

            changed = False
            for key, d in deltas_map.items():
                if d == 0:
                    continue
                pr = index.get(key)
                if not pr:
                    # If delta references a missing rack, ignore negative fixes gracefully, error on positives
                    if d > 0:
                        raise ValueError(f"Rack not found for key={key}")
                    continue
                pr["rack_lock"] = max(0, _as_int(pr.get("rack_lock")) + d)
                changed = True

            if changed:
                product.rack_details = product_racks
                product.save(update_fields=["rack_details"])

    # If the product changed, split the deltas:
    # - Remove old allocations from the old product (deltas = -old_alloc)
    # - Add new allocations to the new product   (deltas =  new_alloc)
    if old_product_id and old_product_id != instance.product_id:
        remove_old = {k: -old_alloc.get(k, 0) for k in old_alloc}
        apply_deltas_to_product(old_product_id, remove_old)
        apply_deltas_to_product(instance.product_id, new_alloc)
    else:
        apply_deltas_to_product(instance.product_id, deltas)

@receiver(post_delete, sender=OrderItem)
def handle_orderitem_rack_lock_delete(sender, instance, **kwargs):
    # Remove rack locks
    update_product_rack_lock(instance.product, instance.rack_details, diff=-1)

def update_product_rack_lock(product, rack_details, diff=1):
    """
    Update the rack_lock in product.rack_details based on rack_details.
    diff: +1 to lock, -1 to unlock
    """
    product_racks = product.rack_details or []
    changed = False

    # Build quick index: (rack_id, column_name) -> rack dict
    index = {(pr.get("rack_id"), pr.get("column_name")): pr for pr in product_racks}

    # First pass (validation if locking)
    if diff > 0:
        for order_rack in rack_details or []:
            key = (order_rack.get("rack_id"), order_rack.get("column_name"))
            pr = index.get(key)
            if not pr:
                raise ValueError(f"Rack not found for key={key}")
            rack_stock = int(pr.get("rack_stock", 0) or 0)
            rack_lock  = int(pr.get("rack_lock", 0) or 0)
            available  = max(0, rack_stock - rack_lock)
            qty        = int(order_rack.get("quantity", 0) or 0)
            if qty > available:
                raise ValueError(
                    f"Not enough available in rack {key}: need {qty}, available {available}"
                )

    # Second pass (apply)
    for order_rack in rack_details or []:
        key = (order_rack.get("rack_id"), order_rack.get("column_name"))
        pr = index.get(key)
        if not pr:
            continue
        qty = int(order_rack.get("quantity", 0) or 0)
        new_lock = int(pr.get("rack_lock", 0) or 0) + diff * qty
        pr["rack_lock"] = max(0, new_lock)
        changed = True

    if changed:
        product.rack_details = product_racks
        product.save(update_fields=["rack_details"])
    
        
class ProductRack(models.Model):
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name="racks")
    rack_id = models.PositiveIntegerField()
    rack_name = models.CharField(max_length=50, blank=True)
    column_name = models.CharField(max_length=50, blank=True)
    usability = models.CharField(max_length=20, choices=[("usable","usable"),("damaged","damaged")])
    rack_stock = models.PositiveIntegerField(default=0)
    locked_stock = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ("product", "rack_id", "column_name", "usability")
        
class OrderItemRackAllocation(models.Model):
    order_item = models.ForeignKey(OrderItem, on_delete=models.CASCADE, related_name="rack_allocations")
    product_rack = models.ForeignKey("beposoft_app.ProductRack", on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    class Meta:
        unique_together = ("order_item", "product_rack")
        
        
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
        
        prefix = f"P{self.company.prefix}" # Retrieve prefix from the associated Company
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
        ('cod_return', 'COD Return'),
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
    rack_details = models.JSONField(default=list, blank=True, null=True)
    selected_racks = models.JSONField(default=list, blank=True, null=True)
    cod_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="COD return amount if applicable"
    )
    

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


class DataLog(models.Model):
    """
    Minimal append-only log for any API action.
    Stores user (from token), before/after data snapshots, and timestamp.
    """
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='data_logs')
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, null=True, blank=True, related_name='data_logs')
    before_data = models.JSONField(null=True, blank=True, default=dict)
    after_data  = models.JSONField(null=True, blank=True, default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "data_log"
        indexes = [models.Index(fields=['created_at'])]

    def __str__(self):
        u = self.user.name if self.user else "anonymous"
        return f"[DataLog] by {u} @ {self.created_at:%Y-%m-%d %H:%M:%S} (id={self.pk})"
    

class ContactInfo(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    phone = models.CharField(max_length=100)
    state = models.ForeignKey(State, on_delete=models.CASCADE)
    email = models.EmailField(max_length=100, null=True, blank=True)
    address = models.CharField(max_length=100, null=True, blank=True)
    zipcode = models.CharField(max_length=100, null=True, blank=True)
    description = models.CharField(max_length=200, null=True, blank=True)
    note = models.CharField(max_length=200, null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="contactinfo", null=False, blank=False)
    district = models.ForeignKey(State, on_delete=models.SET_NULL, null=True, blank=True, related_name="contactdistrict")

    class Meta:
        db_table = "contactinfo"

    def __str__(self):
        return self.first_name
    

class CallReport(models.Model):
    STATUS_CHOICES = [
        ('Active','active'),
        ('Productive','productive'),
        ('Inactive','inactive')
    ]
    customer_name = models.CharField(max_length=100, null=True, blank=True)
    duration = models.CharField(max_length=100)
    invoice = models.CharField(max_length=50, null=True, blank=True)
    amount = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=100, choices=STATUS_CHOICES, default='Active')
    description = models.CharField(max_length=200, null=True, blank=True)
    note = models.CharField(max_length=100, null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=100, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    date = models.DateField(null=True, blank=True)
    Customer = models.ForeignKey(ContactInfo, on_delete=models.CASCADE, null=True, blank=True, related_name="call_report")
    audio_file = models.FileField(upload_to='call_audios/', null=True, blank=True)
    call_datetime = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "callreport"

    def __str__(self):
        return f"{self.customer_name} - {self.invoice}"
    

class Questionnaire(models.Model):
    questions = models.TextField(null=True, blank=True)
    family = models.ForeignKey(Family, on_delete=models.CASCADE, related_name="questionnaires")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_questionnaires")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "questionnaire"

    def __str__(self):
        return f"{self.id} - {self.family}"
    

class Answers(models.Model):
    answer = models.TextField(null=True, blank=True)
    note = models.CharField(max_length=100, null=True, blank=True)
    question = models.ForeignKey(Questionnaire, on_delete=models.CASCADE, related_name="answers")
    family = models.ForeignKey(Family, on_delete=models.CASCADE, related_name="family_answers")
    added_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_answers")
    created_at = models.DateTimeField(auto_now_add=True)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name="customer_answers", null=True, blank=True)

    class Meta:
        db_table = "answers"

    def __str__(self):
        return f"{self.id} - {self.family}"