from rest_framework import serializers 
from .models import *
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.db.models import Sum
from datetime import datetime
from django.db.models import F, Sum, FloatField
from django.db.models.functions import Cast
from datetime import date
from bepocart.models import *
from bepocart.serializers import *


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    retype_password = serializers.CharField(write_only=True, required=True)
    phone = serializers.CharField(required=True)  # Assuming phone is a required field

    class Meta:
        model = User
        fields = ['name', 'email', 'username', 'password', 'retype_password', 'phone']

    def validate(self, data):
        if data['password'] != data['retype_password']:
            raise serializers.ValidationError("Passwords do not match")
        
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("A user with this email already exists")
        
        if User.objects.filter(phone=data['phone']).exists():
            raise serializers.ValidationError("A user with this phone number already exists")
        
        return data
    
    def create(self, validated_data):
        validated_data.pop('retype_password')

        user = User.objects.create(**validated_data)
        
        return user


    

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    


class UserSerializer(serializers.ModelSerializer):
    family_id = serializers.IntegerField(source='family.id', read_only=True)
    family_name = serializers.CharField(source='family.name', read_only=True)
    country_code_name = serializers.CharField(source='country_code.country_code', read_only=True)
    # department_name = serializers.CharField(source='department.name', read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'eid', 'name', 'username', 'email', 'phone',
            'alternate_number', 'password', 'image', 'date_of_birth',
            'allocated_states', 'gender', 'marital_status',
            'driving_license', 'driving_license_exp_date',
            'employment_status', 'designation', 'grade', 'address',
            'state', 'country', 'join_date', 'confirmation_date',
            'termination_date', 'supervisor_id', 'department_id',
            'warehouse_id', 'country_code', 'signatur_up',
            'approval_status', 'family', 'created_at', 'updated_at',
            'family_id', 'family_name','country_code_name'
        ]

    def validate(self, data):
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("A user with this email already exists")
        
        if User.objects.filter(phone=data['phone']).exists():
            raise serializers.ValidationError("A user with this phone number already exists")
        
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("A user with this username already exists")
        
        return data


class UserUpdateSerilizers(serializers.ModelSerializer):
    family_name = serializers.CharField(source='family.name', read_only=True)
    supervisor_name=serializers.CharField(source='supervisor_id.name',read_only=True)
    department_name=serializers.CharField(source='department_id.name',read_only=True)
    allocated_states_names = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name',
        source='allocated_states'
    )
   
    class Meta:
        model = User
        fields = "__all__"
   

class StaffSerializer(serializers.ModelSerializer):
    department = serializers.CharField(source='department_id.name', read_only=True)

    class Meta:
        model = User
        fields = ['id','eid','name','department','join_date','phone','email','designation','family','approval_status']


class CustomerTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerType
        fields = ["id", "type_name"]


class CustomerSerilizers(serializers.ModelSerializer):
    state_name = serializers.CharField(source='State.name', read_only=True)
    manager_name = serializers.CharField(source='User.name', read_only=True)
    
    class Meta:
        model = Customers
        fields = '__all__'
        extra_fields = ['state_name', 'manager_name']  # Add these if you want to keep them
        
    def update(self, instance, validated_data):
        # Handle state and manager updates manually if needed
        state_id = self.context['request'].data.get('state')
        if state_id:
            instance.state_id = state_id
            
        manager_name = self.context['request'].data.get('manager')
        if manager_name:
            # Assuming manager is a User and you need to find by name
            try:
                manager = User.objects.get(name=manager_name)
                instance.manager = manager
            except User.DoesNotExist:
                pass
                
        return super().update(instance, validated_data)
       
        
class CustomerModelSerializer(serializers.ModelSerializer):
    gst = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    gst_confirm = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    customer_type = serializers.PrimaryKeyRelatedField(
        queryset=CustomerType.objects.all(),
        required=False, allow_null=True
    )
    class Meta:
        model = Customers
        fields = [
            'id', 'gst', 'name', 'manager', 
            'phone', 'alt_phone', 'email',
            'address', 'zip_code', 'city', 
            'state', 'comment', 'created_at',
            'customer_type', 'gst_confirm'
        ]

    def validate(self, data):
        
        if Customers.objects.filter(phone=data.get('phone')).exists():
            raise serializers.ValidationError({'phone': 'Phone number is already registered.'})

        return data

    # If you want to handle uniqueness checks during updates, override update() method
    def update(self, instance, validated_data):
        phone = validated_data.get('phone', instance.phone)

        # Start a transaction to ensure atomicity
        with transaction.atomic():
            
            # Check if phone is already registered excluding current instance
            if Customers.objects.filter(phone=phone).exclude(pk=instance.pk).exists():
                raise serializers.ValidationError({'phone': 'Phone number is already registered.'})

            # Perform the update operation
            return super().update(instance, validated_data)


class CustomerModelSerializerView(serializers.ModelSerializer):
    state = serializers.CharField(source='state.name', read_only=True)
    state_id = serializers.IntegerField(source='state.pk', read_only=True)
    manager = serializers.CharField(source ='manager.name',read_only=True)
    family = serializers.CharField(source ='manager.family.pk',read_only=True)
    class Meta:
        model = Customers
        fields = "__all__"

class CustomerModelSerializerLimited(serializers.ModelSerializer):
    family=serializers.CharField(source="manager.family.name")
    state_name = serializers.CharField(source="state.name")
    customer_type = serializers.CharField(source="customer_type.type_name", read_only=True)

    class Meta:
        model = Customers
        fields = ['id','name', 'email', 'created_at',
                  'manager','family','phone',
                  'state_name','customer_type', 'gst']          


class ProductsSerializer(serializers.ModelSerializer):
    family = serializers.PrimaryKeyRelatedField(many=True, queryset=Family.objects.all())
    created_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    warehouses = serializers.PrimaryKeyRelatedField(queryset=WareHouse.objects.all(), required=False)
  
    class Meta:
        model = Products
        fields = "__all__"
        

class ProductsAddSerializer(serializers.ModelSerializer):
    family = serializers.PrimaryKeyRelatedField(many=True, queryset=Family.objects.all())
    created_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    warehouses = serializers.PrimaryKeyRelatedField(queryset=WareHouse.objects.all(), required=False)
    product_category = serializers.PrimaryKeyRelatedField(queryset=ProductCategoryModel.objects.all(), required=False)
    class Meta:
        model = Products
        exclude = ["exclude_price"]                 


class CustomerSerilizers(serializers.ModelSerializer):
    state = serializers.CharField(source='state.name', read_only=True)
    manager = serializers.CharField(source ='manager.name',read_only=True)
    customer_type = serializers.CharField(source='customer_type.type_name', read_only=True)

    class Meta :
        model = Customers
        fields = "__all__"

class CustomerOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customers
        fields = ['id','name']

class CustomerEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customers
        fields = "__all__"


class SingleProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = SingleProducts
        fields = "__all__"
        
class FamilySerializer(serializers.ModelSerializer):
    class Meta:
        model = Family
        fields = "__all__"
        

class CountryCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CountryCode
        fields = ['id', 'country_code', 'country_name']     
        
    
class ProductSingleviewSerializres(serializers.ModelSerializer):
    variantIDs = serializers.SerializerMethodField()
    images = serializers.SerializerMethodField()
    product_category_name = serializers.SerializerMethodField()

    class Meta:
        model = Products
        fields = "__all__"

    def get_product_category_name(self, obj):
        """Return category name safely, even if null."""
        return obj.product_category.category_name if obj.product_category else None

    def get_variantIDs(self, obj):
        """
        If the product is a variant, return all variants for the same groupID,
        ensuring the current product is not included and preventing duplicates.
        """
        if obj.type == 'variant':  # Check if the product is a variant
            # Filter products with the same groupID but exclude the current product
            variants = Products.objects.filter(groupID=obj.groupID).exclude(id=obj.id)
            
            # Track unique attributes to avoid duplicates
            seen_attributes = set()
            variant_list = []

            for variant in variants:
                if variant.image:
                    selected_image = variant.image.url  # Use the updated image directly
                else:
                    # Fetch images for each variant from SingleProducts
                    variant_images = SingleProducts.objects.filter(product=variant.pk)
                    image_urls = [img.image.url for img in variant_images if img.image]

                    # Use first image from SingleProducts if no variant image is set
                    selected_image = image_urls[0] if image_urls else None  


               

                if variant.name not in seen_attributes:
                    seen_attributes.add(variant.name)
                    variant_list.append({
                        "id": variant.pk,
                        "groupID": variant.groupID,
                        "name": variant.name if variant.name else None,  
                        "stock": variant.stock,
                        "locked_stock":variant.locked_stock,
                        
                        "image": selected_image, # Image URL handling
                        "color":variant.color if variant.color else None,
                        "size": variant.size if variant.size else None,
                        "selling_price": variant.selling_price , # Selling price field
                        "retail_price": variant.retail_price,  
                        "created_user":variant.created_user.name,
                        "approval_status":variant.approval_status,

                        "product_category_id": variant.product_category.id if variant.product_category else None,
                        "product_category_name": variant.product_category.category_name if variant.product_category else None,
                        
                    })

            return variant_list
        return [] 
    
    def get_images(self, obj):
        """Fetch images dynamically using related_name."""
        return [img.image.url for img in obj.images.all()]  
    
    
        

class ProductSerializerView(serializers.ModelSerializer):
    variantIDs = serializers.SerializerMethodField()
    images = serializers.SerializerMethodField()  # Fetch images dynamically

    warehouse_name = serializers.CharField(source='warehouse.name', read_only=True)
    

    class Meta:
        model = Products
        fields = "__all__"

    def to_representation(self, instance):
        data = super().to_representation(instance)

    # Fetch the main product with the same groupID
        main_product = Products.objects.filter(groupID=instance.groupID).order_by('id').first()


        if instance.type == 'variant' and main_product:
            if not data.get('landing_cost'):
                data['landing_cost'] = main_product.landing_cost
            if not data.get('retail_price'):
                data['retail_price'] = main_product.retail_price
            if not data.get('hsn_code'):
                data['hsn_code'] = main_product.hsn_code 
        data['warehouse_name'] = instance.warehouse.name if instance.warehouse else (
        main_product.warehouse.name if main_product and main_product.warehouse else None
    )          

        return data      

   

    
       
       
    
    
    def get_variantIDs(self, obj):
        

        """
        Fetch variant details for the same groupID, including images.
        """
        main_product = Products.objects.filter(groupID=obj.groupID).order_by('id').first()

        if main_product:  # Ensure correct check for 'variant'
            variants = Products.objects.filter(groupID=obj.groupID)
            variant_list = []
            for variant in variants:
                # If the product itself has an updated image, use it.
                if variant.image:
                    selected_image = variant.image.url  
                else:
                    # Fetch images for each variant from SingleProducts
                    variant_images = SingleProducts.objects.filter(product=variant.pk)
                    image_urls = [img.image.url for img in variant_images if img.image]

                    # Use the first available image from SingleProducts if product.image is missing
                    selected_image = image_urls[0] if image_urls else None 

                hsn_code = variant.hsn_code if variant.hsn_code and variant.hsn_code.strip() else main_product.hsn_code
                
            

            # ✅ Always inherit Warehouse Name from main product if missing
                warehouse_name = variant.warehouse.name if variant.warehouse else (
                    main_product.warehouse.name if main_product.warehouse else None
                )
                

          
                # Fetch images for each variant
                
                variant_list.append({
                    "id": variant.pk,
                    "groupID": variant.groupID,
                    "name": variant.name,
                    "hsn_code":hsn_code,
                    "image":selected_image,  # Use the first image or None
                    "price": variant.selling_price,
                    "color": variant.color if variant.color else None,
                    "size": variant.size if variant.size else None,
                    "stock": variant.stock,
                    "created_user": variant.created_user.name,
                    "warehouse_name": warehouse_name
                    
                   
                })

            return variant_list
        return []
    def get_images(self, obj):
        """Fetch images dynamically using the related name 'images'."""
        return [img.image.url for img in obj.images.all()]  
    

    
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = "__all__"


class DepartmentSerilizers(serializers.ModelSerializer):
    class Meta :
        model = Departments
        fields = "__all__"



class StateSerializers(serializers.ModelSerializer):
    class Meta:
        model = State
        fields = "__all__"


class DistrictSerializer(serializers.ModelSerializer):
    state_name = serializers.CharField(source='state.name', read_only=True)
    class Meta:
        model = Districts
        fields = "__all__"

class SupervisorSerializerView(serializers.ModelSerializer):
    department = serializers.CharField(source='department.name', read_only=True)
    
    class Meta:
        model = Supervisor
        fields = ["id","name","department"]
        
class SupervisorSerializers(serializers.ModelSerializer):
    class Meta:
        model = Supervisor
        fields = "__all__"

class SupervisorViewSerializers(serializers.ModelSerializer):
    department_name = serializers.CharField(source='department.name', read_only=True)
    class Meta:
        model = Supervisor
        fields = ['id', 'name', 'department', 'department_name']


class ShippingSerializers(serializers.ModelSerializer):
    class Meta:
        model = Shipping
        fields = "__all__"

    def create(self, validated_data):
        created_user = self.context['created_user']
        
        validated_data['created_user'] = created_user
        return Shipping.objects.create(**validated_data)
    
    
    
class ShippingAddressView(serializers.ModelSerializer):
    state = serializers.CharField(source='state.name', read_only=True)
    class Meta:
        model = Shipping
        fields = ["id","name","address","zipcode","email",
                  "city","phone","alt_phone","state"]



class SingleProductsViewSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source="product.name")
    class Meta:
        model = SingleProducts 
        fields = ['id','product','image','name']

    

class SingleProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = SingleProducts
        fields = "__all__"
        
        
class ExistedOrderAddProductsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = "__all__"
        
class OrderItemUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = "__all__"
   
class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ['product', 'name', 'description', 'rate', 'tax', 'quantity', 'price']
        

class WarehouseOrderItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source="product.name", default=None)
    order_invoice = serializers.CharField(source="order.invoice", default=None)
    product_image = serializers.ImageField(source="product.image", default=None)
    product_rack = serializers.CharField(source="product.rack_details", default=None)
    class Meta:
        model = WarehouseOrderItem
        fields = "__all__"


class WarehouseOrderSerializer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name", default=None)
    warehouses_name = serializers.CharField(source="warehouses.name", default=None)
    receiiver_warehouse_name = serializers.CharField(source="receiiver_warehouse.name", default=None)
    company_name = serializers.CharField(source="company.name", default=None)
    items = WarehouseOrderItemSerializer(many=True, read_only=True)
    class Meta:
        model = WarehouseOrder
        fields = "__all__"

class WarehouseOrderGetSerializer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name", default=None)
    warehouses_name = serializers.CharField(source="warehouses.name", default=None)
    receiiver_warehouse_name = serializers.CharField(source="receiiver_warehouse.name", default=None)
    company_name = serializers.CharField(source="company.name", default=None)
    class Meta:
        model = WarehouseOrder
        fields = "__all__"

class OrderSerializer(serializers.ModelSerializer):
    cod_amount = serializers.FloatField(required=False, allow_null=True)
    shipping_mode = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Order
        fields = "__all__"

    # Custom validation to make `cod_amount` not required when `shipping_mode` is provided
    def validate(self, data):
        # If shipping_mode is provided, cod_amount is not required
        if 'shipping_mode' in data and data['shipping_mode'] is not None:
            if 'cod_amount' in data and data['cod_amount'] is None:
                raise serializers.ValidationError({'cod_amount': 'cod_amount cannot be null if shipping_mode is provided.'})
        
        # If cod_amount is provided, ensure shipping_mode can still be optional
        if 'cod_amount' in data and data['cod_amount'] is not None:
            if 'shipping_mode' in data and data['shipping_mode'] is None:
                raise serializers.ValidationError({'shipping_mode': 'shipping_mode cannot be null if cod_amount is provided.'})

        return data
  

class OrderMonthSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='customer.name')
    customer_id = serializers.CharField(source='customer.id', default=None)
    company_name = serializers.CharField(source='company.name', default=None)
    warehouse_name = serializers.CharField(source='warehouses.name', default=None)
    family_name = serializers.CharField(source='family.name', default=None)
    family_id = serializers.CharField(source='family.id', default=None)
    staff_name = serializers.CharField(source='manage_staff.name', default=None)
    staff_id = serializers.CharField(source='manage_staff.id', default=None)

    class Meta:
        model = Order
        fields = [
            'id', 'invoice', 'order_date', 'status', 'total_amount', 'payment_status',
            'payment_method', 'cod_amount', 'customer_name', 'company_name', 'warehouse_name', 
            'family_name','staff_name','customer_id','family_id','staff_id'
        ]
        


class BankAccountTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccountType 
        fields = "__all__"

class BankSerializer(serializers.ModelSerializer):
    # created_user = serializers.CharField(source="created_user.name")
    class Meta:
        model = Bank
        fields = "__all__"

class Bankserializers(serializers.ModelSerializer):
    class Meta:
        model = Bank
        fields = ['id', 'name'] 
        
class BankReceiptSerializer(serializers.ModelSerializer):
    created_by_name = serializers.ReadOnlyField(source='created_by.name')
    bank_name = serializers.ReadOnlyField(source='bank.name')
    class Meta:
        model = BankReceipt
        fields = '__all__'
        read_only_fields = ['payment_receipt']

class AdvanceReceiptSerializer(serializers.ModelSerializer):
    customer = serializers.PrimaryKeyRelatedField(queryset=Customers.objects.all(), required=False, allow_null=True)
    bank = serializers.PrimaryKeyRelatedField(queryset=Bank.objects.all())
    created_by = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False)
    created_by_name = serializers.ReadOnlyField(source='created_by.name')
    bank_name = serializers.ReadOnlyField(source='bank.name')
    customer_name = serializers.ReadOnlyField(source='customer.name')

    class Meta:
        model = AdvanceReceipt
        fields = [
            'id', 'customer', 'amount', 'bank', 'transactionID','payment_receipt',
            'received_at', 'created_by', 'created_by_name', 'remark','customer_name','bank_name'
        ]
        read_only_fields = ['id', 'payment_receipt']

class PaymentRecieptsViewSerializers(serializers.ModelSerializer):
    created_by = serializers.CharField(source="created_by.name")
    bank = serializers.CharField(source="bank.name")
    class Meta :
        model = PaymentReceipt
        fields = '__all__'
        

class OrderItemModelSerializer(serializers.ModelSerializer):
    products = serializers.CharField(source="product.rack_details")
    image=serializers.ImageField(source="product.image")
    name=serializers.CharField(source="product.name")
    actual_price = serializers.SerializerMethodField()
    exclude_price = serializers.SerializerMethodField()
    price_discount = serializers.SerializerMethodField()
  
    class Meta:
        model = OrderItem
        fields = fields = [
            "id",
            "name",
            "order",
            "product",
            "variant",
            "size",
            "description",
            "rate",
            "tax",
            "discount",
            "quantity",
            "actual_price",
            "exclude_price",
            "price_discount",
            "image",
            "products",
            "rack_details",
        ]
    def get_name(self, obj):
        # Check if the product is a single or variant type
        if obj.product.type == "single":
            return obj.product.name
        elif obj.variant:
            return obj.variant.name
        return None
        
    def get_price_discount(self, obj):
        rate = obj.rate or Decimal('0')
        discount = obj.discount or Decimal('0')
        price_discount = max(rate - discount, Decimal('0'))

        return round(price_discount, 2)

        
    from decimal import Decimal

    def get_exclude_price(self, obj):
        rate = obj.rate or Decimal('0')
        discount = obj.discount or Decimal('0')
        tax = obj.product.tax or 0  # tax is likely an integer

        total_price = max(rate - discount, Decimal('0'))
        exclude_price = total_price / (Decimal('1') + (Decimal(tax) / Decimal('100')))

        return round(exclude_price, 2)

    
    def get_actual_price(self, obj):
        # directly use exclude_price
        return self.get_exclude_price(obj)
    

class GSTOrderItemModelSerializer(serializers.ModelSerializer):
    name=serializers.CharField(source="product.name")
    hsn=serializers.CharField(source="product.hsn_code")
    actual_price = serializers.SerializerMethodField()
    exclude_price = serializers.SerializerMethodField()
    price_discount = serializers.SerializerMethodField()
  
    class Meta:
        model = OrderItem
        fields = fields = [
            "id",
            "name",
            "order",
            "product",
            "hsn",
            "rate",
            "tax",
            "discount",
            "quantity",
            "actual_price",
            "exclude_price",
            "price_discount",
        ]
    def get_name(self, obj):
        # Check if the product is a single or variant type
        if obj.product.type == "single":
            return obj.product.name
        elif obj.variant:
            return obj.variant.name
        return None
        
    def get_price_discount(self, obj):
        rate = obj.rate or Decimal('0')
        discount = obj.discount or Decimal('0')
        price_discount = max(rate - discount, Decimal('0'))

        return round(price_discount, 2)

        
    from decimal import Decimal

    def get_exclude_price(self, obj):
        rate = obj.rate or Decimal('0')
        discount = obj.discount or Decimal('0')
        tax = obj.product.tax or 0  # tax is likely an integer

        total_price = max(rate - discount, Decimal('0'))
        exclude_price = total_price / (Decimal('1') + (Decimal(tax) / Decimal('100')))

        return round(exclude_price, 2)

    
    def get_actual_price(self, obj):
        # directly use exclude_price
        return self.get_exclude_price(obj)
    

    
class FamilyOrderWarehouseModelSerilizer(serializers.ModelSerializer):
    class Meta:
        model = Warehousedata
        fields = ['id','box','tracking_id']


# class  WarehousedataSerializer(serializers.ModelSerializer):
#     customer = serializers.CharField(source="order.billing_address.name")
#     phone=serializers.CharField(source="order.billing_address.phone")
#     zip_code=serializers.CharField(source="order.billing_address.zipcode")
#     invoice = serializers.CharField(source="order.invoice")
#     family = serializers.CharField(source="order.family.name")
#     packed_by=serializers.CharField(source="packed_by.name")
#     packed_by_id=serializers.CharField(source="packed_by.id")
#     parcel_service_id=serializers.CharField(source="parcel_service.id")
#     checked_by = serializers.SerializerMethodField()
#     verified_by = serializers.SerializerMethodField()
#     cod_amount=serializers.IntegerField(source="order.cod_amount")
#     order_state = serializers.CharField(source="order.billing_address.state")

#     def get_checked_by(self, obj):
#         return obj.checked_by.name if obj.checked_by is not None else None

#     def get_verified_by(self, obj):
#         return obj.verified_by.name if obj.verified_by is not None else None


#     class Meta:
#         model = Warehousedata
#         fields = [
#             'id', 'box', 'weight', 'length', 'breadth', 'height', 'image','image_before','cod_amount',
#             'parcel_service', 'tracking_id', 'shipping_charge', 'status', 'packed_by_id', 'parcel_service_id',
#             'shipped_date', 'order', 'packed_by','verified_by','checked_by', 'customer','phone','order_state',
#             'zip_code', 'invoice', 'family','actual_weight','parcel_amount','postoffice_date','message_status'
#         ]

#     def to_representation(self, instance):
#         data = super().to_representation(instance)
#         # Handle None for parcel_service
#         data['parcel_service'] = (
#             instance.parcel_service.name if instance.parcel_service else None
#         )
#         return data
        

class WarehousedataSerializer(serializers.ModelSerializer):
    customer = serializers.CharField(source="order.billing_address.name")
    phone = serializers.CharField(source="order.billing_address.phone")
    zip_code = serializers.CharField(source="order.billing_address.zipcode")
    invoice = serializers.CharField(source="order.invoice")
    family = serializers.CharField(source="order.family.name")
    packed_by = serializers.CharField(source="packed_by.name")
    packed_by_id = serializers.CharField(source="packed_by.id")

    parcel_service_id = serializers.SerializerMethodField()
    parcel_service_name = serializers.SerializerMethodField()

    checked_by = serializers.SerializerMethodField()
    verified_by = serializers.SerializerMethodField()

    cod_amount = serializers.IntegerField(source="order.cod_amount")
    box_count = serializers.IntegerField( source="order.box_count",)
    order_state = serializers.CharField(source="order.billing_address.state")

    class Meta:
        model = Warehousedata
        fields = [
            'id', 'box', 'weight', 'length', 'breadth', 'height',
            'image', 'image_before', 'cod_amount', 'box_count',
            'parcel_service_id', 'parcel_service_name',
            'tracking_id', 'shipping_charge', 'status',
            'packed_by_id', 'shipped_date', 'order',
            'packed_by', 'verified_by', 'checked_by',
            'customer', 'phone', 'order_state',
            'zip_code', 'invoice', 'family',
            'actual_weight', 'parcel_amount',
            'postoffice_date', 'message_status'
        ]

    def get_parcel_service_id(self, obj):
        return obj.parcel_service.id if obj.parcel_service else None

    def get_parcel_service_name(self, obj):
        return obj.parcel_service.name if obj.parcel_service else None

    def get_checked_by(self, obj):
        return obj.checked_by.name if obj.checked_by else None

    def get_verified_by(self, obj):
        return obj.verified_by.name if obj.verified_by else None


        
class WarehouseUpdateSerializers(serializers.ModelSerializer):
    class Meta :
        model = Warehousedata
        fields = '__all__'
        

class LedgerSerializers(serializers.ModelSerializer):
    company = serializers.CharField(source="company.name")
    customer_name = serializers.CharField(source="customer.name")

    return_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    refund_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    cod_return_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    exchange_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "invoice",
            "company",
            "customer_name",
            "total_amount",
            "return_amount",
            "refund_amount",
            "cod_return_amount",
            "exchange_amount",
            "order_date",
            "status",
        ]


class GRVLedgerSerializer(serializers.ModelSerializer):
    order_id = serializers.IntegerField(source="order.id", read_only=True)
    invoice = serializers.CharField(source="order.invoice", read_only=True)

    class Meta:
        model = GRVModel
        fields = [
            "id",
            "order_id",
            "invoice",
            "product",
            "quantity",
            "price",
            "cod_amount",
            "remark",
            "status",
            "date",
            "time",
            "note",
        ]



class AttributesModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attributes
        exclude = ['created_user']

class ProductsListViewSerializers(serializers.ModelSerializer):
    class Meta :
        model = Products
        fields = '__all__'


class ProductAttributeModelSerilizer(serializers.ModelSerializer):
    class Meta:
        model = ProductAttribute
        fields = '__all__'
        
        
        
class BepocartSerializers(serializers.ModelSerializer):
    class Meta :
        model = BeposoftCart
        fields = [f.name for f in BeposoftCart._meta.fields]

        
class BepocartSerializersView(serializers.ModelSerializer):
    name = serializers.CharField(source="product.name")
    tax = serializers.FloatField(source="product.tax")
    image = serializers.ImageField(source="product.image")
    selling_price = serializers.FloatField(source="product.selling_price")
    retail_price = serializers.FloatField(source="product.retail_price")
    stock = serializers.IntegerField(source="product.stock")
    locked_stock = serializers.IntegerField(source="product.locked_stock")
    exclude_price = serializers.SerializerMethodField()
    price = serializers.SerializerMethodField()

  
    class Meta:
        model = BeposoftCart
        fields = [
            "id", "product", "quantity", "discount", "note", "created_at","locked_stock","stock",
            "name", "tax", "exclude_price", "image", "selling_price", "retail_price", "price"
        ]
    def get_price(self, obj):
        if obj.price is not None:
            return obj.price
        # Get the user and check if their designation is 'BDO' or 'BDM'
        user = obj.user
        if user.designation in ['BDO', 'BDM']:
            return obj.product.selling_price  # If designation is BDO or BDM, return the selling price
        return obj.product.retail_price
    
    def get_exclude_price(self, obj):
        selling_price = obj.product.selling_price or 0
        discount = obj.discount or 0
        tax = obj.product.tax or 0

        total_price = max(selling_price - discount, 0)
        exclude_price = total_price / (1 + (tax / 100))

        return round(exclude_price, 2) 
    



class PaymentRecieptSerializers(serializers.ModelSerializer):
    created_by_name = serializers.ReadOnlyField(source='created_by.name')
    bank_name = serializers.ReadOnlyField(source='bank.name')
    customer_name = serializers.ReadOnlyField(source='customer.name')
    order_name = serializers.ReadOnlyField(source='order.invoice')
    class Meta :
        model = PaymentReceipt
        fields = '__all__'




class PerfomaInvoiceOrderSerializers(serializers.ModelSerializer):
    warehouse_id = serializers.IntegerField(write_only=True) 
    class Meta :
        model = PerfomaInvoiceOrder
        fields = ["manage_staff", "company", "customer", "invoice", "billing_address",
                  "shipping_mode", "code_charge","order_date", "family", "state", "status", "total_amount",
                   "shipping_charge","note", "warehouse_id"]  # Include warehouse_id

    def create(self, validated_data):
        # Extract the warehouse_id from the validated data
        warehouse_id = validated_data.pop("warehouse_id")
        
        # Create the order object first
        order = super().create(validated_data)
        
        # Now link the warehouse to the order using the warehouse_id
        warehouse = WareHouse.objects.get(id=warehouse_id)
        order.warehouses_obj = warehouse
        order.save()

        return order
       
     

class PerformaOrderListSerilaizer(serializers.ModelSerializer):
    customermame=serializers.CharField(source="customer.name",read_only=True)
    staffname=serializers.CharField(source="manage_staff.name",read_only=True) 
    class Meta:
        model=PerfomaInvoiceOrder
        fields='__all__'       


class CallLogSerializer(serializers.ModelSerializer):
    created_by = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = CallLog
        fields = '__all__'

        
class PerfomaInvoiceProducts(serializers.ModelSerializer):
    images =  serializers.ImageField(source="product.image")
    name = serializers.CharField(source="product.name")
    actual_price = serializers.SerializerMethodField()
    exclude_price = serializers.SerializerMethodField()
    
    class Meta:
        model = PerfomaInvoiceOrderItem
        fields = "__all__"
        
        

    
    def get_actual_price(self, obj):
        # Calculate the actual price based on the product type
        return int(obj.product.selling_price) if obj.product.selling_price is not None else None
    
    def get_exclude_price(self, obj):
        return int(obj.product.exclude_price) if obj.product.exclude_price is not None else None
    

    
        
class PerfomaInvoiceProductsSerializers(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.id")
    manage_staff_name=serializers.CharField(source="manage_staff.name")
    family = serializers.CharField(source="family.id")
    familyname=serializers.CharField(source="family.name")
 
    billing_address = ShippingAddressView(read_only=True)
    customer = CustomerSerilizers(read_only=True)
    payment_receipts =  PaymentRecieptsViewSerializers(many=True,read_only=True)
    customerID = serializers.IntegerField(source="customer.pk")
    perfoma_items = PerfomaInvoiceProducts(many=True,read_only=True)
    company_name=serializers.CharField(source="company.name")
    warehouse_id = serializers.IntegerField(source="warehouses_obj.id", read_only=True)
    class Meta:
        model = PerfomaInvoiceOrder
        fields = ["id","manage_staff","manage_staff_name","company","company_name","customer",
                  "invoice","billing_address",
                  "shipping_mode","code_charge","order_date","family","familyname",
                  "state","status","total_amount",
                  "payment_receipts",
                  "shipping_charge","customerID","perfoma_items","warehouse_id"]
    def to_representation(self, instance):
        # Add manage_staff_designation to the context of nested serializers
        self.context["manage_staff_designation"] = instance.manage_staff.designation
        return super().to_representation(instance)    

        

class CompanyDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = "__all__"
        
        


class WarehouseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Warehousedata
        fields=['box','parcel_service','tracking_id']


class OrderDetailSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='customer.name', read_only=True)  
    staff_name = serializers.CharField(source='manage_staff.name', read_only=True) 
    family_name=serializers.CharField(source='family.name',read_only=True)
    warehouse=WarehouseSerializer(many=True,read_only=True)
    state = serializers.CharField(source='state.name', read_only=True) 
    recived_payment = PaymentRecieptSerializers(many=True,read_only=True)

    
    class Meta:
        model = Order
        fields = "__all__"

class PaymentReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentReceipt
        fields = ['amount']       
        
class AdvancePaymentReceiptSerializer(serializers.ModelSerializer):
    order = serializers.PrimaryKeyRelatedField(queryset=Order.objects.all(), required=False, allow_null=True)
    customer = serializers.PrimaryKeyRelatedField(queryset=Customers.objects.all(), required=True)
    bank = serializers.PrimaryKeyRelatedField(queryset=Bank.objects.all(), required=True)
    created_by = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=True)

    class Meta:
        model = PaymentReceipt
        fields = [
            'id', 'order', 'customer', 'amount', 'bank', 'transactionID',
            'received_at', 'created_by', 'remark'
        ]
        read_only_fields = ['id']

    def create(self, validated_data):
        # If `order` not provided, you can set to None or implement default logic here
        if 'order' not in validated_data:
            validated_data['order'] = None  # Only if model allows null=True for order
        return super().create(validated_data)


class OrderPaymentSerializer(serializers.ModelSerializer):
    recived_payment = PaymentReceiptSerializer(many=True)
    total_paid = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = ['id', 'invoice', 'order_date', 'payment_status', 'status',
                  'recived_payment', 'manage_staff', 'customer', 'total_paid']

    def get_total_paid(self, obj):
        try:
            return obj.recived_payment.annotate(
                amount_decimal=Func(
                    F('amount'),
                    function='CAST',
                    template='%(function)s(%(expressions)s AS DECIMAL)',
                    output_field=DecimalField()
                )
            ).aggregate(total_paid=Sum('amount_decimal'))['total_paid'] or 0
        except Exception as e:
            return f"Error: {str(e)}"
    
class PaymentReceiptSerializerView(serializers.ModelSerializer):
    bankname=serializers.CharField(source="bank.name")
    invoice=serializers.CharField(source="order.invoice")
    customer=serializers.CharField(source="customer.name")
    created_by=serializers.CharField(source="created_by.name")
    class Meta:
        model = PaymentReceipt
        fields = ["id","payment_receipt","amount","transactionID","received_at","remark","order","customer","bank","invoice","created_by","bankname"]



        
    
class WarehouseDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = WareHouse
        fields = "__all__"  


class WarehouseDataSerializer(serializers.ModelSerializer):

    class Meta:
        model = Warehousedata
        fields = [
            "box", "tracking_id"
        ]
        

class TrackingWarehouseDataSerializer(serializers.ModelSerializer):
    volume_weight = serializers.SerializerMethodField()
    average = serializers.SerializerMethodField()
    parcel_service = serializers.CharField(source="parcel_service.name", read_only=True)

    class Meta:
        model = Warehousedata
        fields = [
            "box", "tracking_id", 
            "parcel_amount", "parcel_service",
            "actual_weight", "weight",
            "length", "breadth", "height",
            "postoffice_date", "shipped_date",
            "volume_weight", "average",
        ]

    def get_volume_weight(self, obj):
        try:
            length = float(obj.length)
            breadth = float(obj.breadth)
            height = float(obj.height)
            return round((length * breadth * height) / 6000, 2)
        except (TypeError, ValueError):
            return None

    def get_average(self, obj):
        try:
            parcel_amount = float(obj.parcel_amount)
            actual_weight = float(obj.actual_weight)
            if actual_weight == 0:
                return None
            return round(parcel_amount / (actual_weight / 1000), 2)
        except Exception as e:
            return None



class OrderdetailsSerializer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name", read_only=True)
    staffID = serializers.CharField(source="manage_staff.pk", read_only=True)
    family = serializers.CharField(source="family.name", read_only=True)
    billing_address = ShippingAddressView(read_only=True)
    customer = CustomerOrderSerializer(read_only=True)
    customerID = serializers.IntegerField(source="customer.pk", read_only=True)
    state = serializers.CharField(source="state.name", read_only=True)
    company = serializers.CharField(source="company.name", read_only=True)

    warehouse_data = WarehouseDataSerializer(source="warehouse", many=True, read_only=True)

    class Meta:
        model = Order
        fields = "__all__"
        extra_fields = ['warehouse_data'] 

class GSTOrderSerializer(serializers.ModelSerializer):
    customerName = serializers.CharField(source="customer.name", read_only=True)
    gst = serializers.CharField(source="customer.gst", read_only=True)
    gst_confirm = serializers.CharField(source="customer.gst_confirm", read_only=True)
    address = serializers.CharField(source="billing_address.state.name", read_only=True)
    items = GSTOrderItemModelSerializer(read_only = True,  many=True)
    class Meta:
        model = Order
        fields = ['id', 'invoice', 'order_date', 'gst_confirm',
                  'total_amount', 'payment_status', 
                  'status', 'customer', 'manage_staff',
                  'customerName', 'gst','items', 'address']

        
        
class TrackingdetailsSerializer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name", read_only=True)
    staffID = serializers.CharField(source="manage_staff.pk", read_only=True)
    family = serializers.CharField(source="family.name", read_only=True)
    customerID = serializers.IntegerField(source="customer.pk", read_only=True)
    customerName = serializers.CharField(source="customer.name", read_only=True)
    state = serializers.CharField(source="state.name", read_only=True)

    warehouse_data = TrackingWarehouseDataSerializer(source="warehouse", many=True, read_only=True)

    class Meta:
        model = Order
        fields = "__all__"
        extra_fields = ['warehouse_data'] 


# class ProductWiseReportSerializer(serializers.ModelSerializer):
#     product_id = serializers.IntegerField(source='product.id')
#     product_name = serializers.CharField(source='product.name')
#     order_id = serializers.IntegerField(source='order.id')
#     invoice = serializers.CharField(source='order.invoice')
#     staff_id = serializers.IntegerField(source='order.manage_staff.id')
#     staff_name = serializers.CharField(source='order.manage_staff.name')
#     staff_family = serializers.CharField(source='order.manage_staff.family.name')
#     allocated_states = serializers.SerializerMethodField()
#     order_date = serializers.CharField(source='order.order_date')
#     order_state = serializers.CharField(source='order.state.name')
#     family_name = serializers.CharField(source='order.family.name')
#     category_name = serializers.CharField(source='product.product_category.category_name')
#     category_id = serializers.CharField(source='product.product_category')

#     class Meta:
#         model = OrderItem
#         fields = [
#             'product_id', 'product_name','quantity',
#             'order_id', 'invoice','order_state',
#             'staff_id', 'staff_name','staff_family',
#             'allocated_states', 'order_date','family_name',
#             'category_name', 'category_id'
#         ]

#     def get_allocated_states(self, obj):
#         return [state.name for state in obj.order.manage_staff.allocated_states.all()]

class ProductWiseReportSerializer(serializers.ModelSerializer):
    product_id = serializers.IntegerField(source='product.id')
    product_name = serializers.CharField(source='product.name')
    order_id = serializers.IntegerField(source='order.id')
    invoice = serializers.CharField(source='order.invoice')
    staff_id = serializers.IntegerField(source='order.manage_staff.id')
    staff_name = serializers.CharField(source='order.manage_staff.name')
    staff_family = serializers.CharField(source='order.manage_staff.family.name')
    allocated_states = serializers.SerializerMethodField()
    order_date = serializers.CharField(source='order.order_date')
    order_state = serializers.CharField(source='order.state.name')
    family_name = serializers.CharField(source='order.family.name')
    category_name = serializers.SerializerMethodField()
    category_id = serializers.SerializerMethodField()

    class Meta:
        model = OrderItem
        fields = [
            'product_id', 'product_name', 'quantity',
            'order_id', 'invoice', 'order_state',
            'staff_id', 'staff_name', 'staff_family',
            'allocated_states', 'order_date', 'family_name',
            'category_name', 'category_id'
        ]

    def get_allocated_states(self, obj):
        return [state.name for state in obj.order.manage_staff.allocated_states.all()]

    def get_category_name(self, obj):
        if obj.product.product_category:
            return obj.product.product_category.category_name
        return None

    def get_category_id(self, obj):
        if obj.product.product_category:
            return obj.product.product_category.id
        return None


class OrderModelSerilizer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name")
    staffID = serializers.CharField(source="manage_staff.pk")
    family = serializers.CharField(source="family.name")
    bank  = BankSerializer(read_only=True)
    billing_address = ShippingAddressView(read_only=True)
    customer = CustomerSerilizers(read_only=True)
    payment_receipts =  PaymentRecieptsViewSerializers(many=True,read_only=True)
    customerID = serializers.IntegerField(source="customer.pk")
    items = OrderItemModelSerializer(read_only = True,  many=True)
    warehouse=WarehousedataSerializer(many=True,read_only=True)
    company = CompanyDetailsSerializer(read_only=True)
    recived_payment = PaymentRecieptsViewSerializers(read_only=True, many=True)
    state = serializers.CharField(source="state.name")

    
    class Meta:
        model = Order
        fields = "__all__"
        
class FamilyOrderModelSerilizer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name")
    staffID = serializers.CharField(source="manage_staff.pk")
    family = serializers.CharField(source="family.name")
    billing_address = ShippingAddressView(read_only=True)
    customer = serializers.CharField(source="customer.name", read_only=True)
    customerID = serializers.IntegerField(source="customer.pk", read_only=True)
    warehouse=FamilyOrderWarehouseModelSerilizer(many=True,read_only=True)
    state = serializers.CharField(source="state.name")

    
    class Meta:
        model = Order
        fields = "__all__"


class OrderStateWiseSerializer(serializers.ModelSerializer):
    manage_staff = serializers.CharField(source="manage_staff.name")
    staffID = serializers.CharField(source="manage_staff.pk")
    family = serializers.CharField(source="family.name")
    customerID = serializers.IntegerField(source="customer.pk")
    state = serializers.CharField(source="state.name")
    
    class Meta:
        model = Order
        fields = "__all__"


class WarehouseBoxesDataSerializer(serializers.ModelSerializer):
    class Meta:
        model=Warehousedata
        fields = "__all__"
            
       

# class OrderModelSerilizer(serializers.ModelSerializer):
    # manage_staff = serializers.CharField(source="manage_staff.name")
    # family = serializers.CharField(source="family.name")
    # bank  = BankSerializer(read_only=True)
    # billing_address = ShippingAddressView(read_only=True)
    # customer = CustomerSerilizers(read_only=True)
    # payment_receipts =  PaymentRecieptsViewSerializers(many=True,read_only=True)
    # customerID = serializers.IntegerField(source="customer.pk")
    # warehouse_orders=WarehousedataSerializer(many=True,read_only=True)


    # class Meta:
    #     model = Order
    #     fields = ["id","manage_staff","updated_at","company","customer","invoice","billing_address","shipping_mode","code_charge","order_date","family","state","payment_status","status","total_amount","bank","payment_method","payment_receipts","shipping_charge","customerID","warehouse_orders"]

class GRVSerializer(serializers.ModelSerializer):
    customer = serializers.CharField(source="order.customer.name")
    staff=serializers.CharField(source='order.manage_staff.name')
    invoice = serializers.CharField(source = "order.invoice")
    order_date = serializers.CharField(source="order.order_date")
    family=serializers.IntegerField(source="order.family.id")
    # rack_products = serializers.SerializerMethodField()
    # product_id = serializers.SerializerMethodField()
    rack_products = serializers.JSONField(source='product_id.rack_details', read_only=True)
    
    class Meta:
        model=GRVModel
        fields=['order','id','product','family',
                'returnreason','price','quantity',
                'remark','note','status','customer',
                'invoice','staff',"order_date",'date',
                'time','updated_at','product_id','cod_amount',
                'rack_details','rack_products','selected_racks']
        
    # def get_product_id(self, obj):
    #     return obj.product_id.id if obj.product_id else None
    
    # def get_rack_products(self, obj):
    #     if obj.product_id and obj.product_id.rack_details is not None:
    #         return obj.product_id.rack_details
    #     return [] 
        
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if 'time' in representation and representation['time']:
            try:
                # Convert stored time into 12-hour format for the response
                time_obj = datetime.strptime(representation['time'], '%H:%M:%S')  # Assuming HH:MM:SS storage format
                representation['time'] = time_obj.strftime('%I:%M %p')  # Convert to hh:mm AM/PM
            except ValueError:
                pass  # Leave the time as-is if parsing fails
        return representation  
        # Customize the output format of the time field
           

# class GRVModelSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = GRVModel
#         fields = ['order', 'product', 'returnreason', 'rack_details',
#                   'price', 'quantity', 'remark', 'status','selected_racks', 
#                   'date', 'time', 'note', 'updated_at','product_id']


class GRVModelSerializer(serializers.ModelSerializer):
    # Accept a plain integer for product_id (FK to Products)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Products.objects.all(),
        required=False, allow_null=True
    )

    class Meta:
        model = GRVModel
        fields = [
            'order', 'product', 'returnreason', 'rack_details',
            'price', 'quantity', 'remark', 'status', 'selected_racks',
            'date', 'time', 'note', 'updated_at', 'product_id','cod_amount'
        ]
        extra_kwargs = {
            'remark': {'required': False, 'allow_null': True},
            'status': {'required': False, 'allow_null': True},
            'date':   {'required': False, 'allow_null': True},
            'time':   {'required': False, 'allow_null': True},
            'note':   {'required': False, 'allow_null': True},
            'updated_at': {'read_only': True},
            'rack_details': {'required': False},
            'selected_racks': {'required': False},
        }



class StateBaseOrderSerializers(serializers.ModelSerializer):
    waiting_orders = serializers.SerializerMethodField()
    order_date = serializers.SerializerMethodField()

    class Meta:
        model = State
        fields = ['id', 'name', 'order_date', 'waiting_orders']

    def get_waiting_orders(self, obj):
        waiting_statuses = ['Pending', 'Waiting For Confirmation']
        orders = Order.objects.filter(state=obj, status__in=waiting_statuses)
        return OrderSerializer(orders, many=True).data

    def get_order_date(self, obj):
        # Get the order date from the first waiting order
        first_waiting_order = Order.objects.filter(state=obj, status__in=['Pending', 'Waiting For Confirmation']).first()
        if first_waiting_order:
            return first_waiting_order.order_date
        return None
    

class OrderImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderImage
        fields = ['id', 'order', 'image', 'uploaded_at']
        
class OrderPaymentImagesSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderPaymentImages
        fields = ['id', 'order', 'image', 'uploaded_at']


class WareHouseSerializer(serializers.ModelSerializer):
    invoice=serializers.CharField(source="order.invoice")
    customer=serializers.CharField(source="order.customer.name")
    customer_id=serializers.CharField(source="order.customer.id")
    order_date=serializers.DateTimeField(source="order.order_date")
    volume_weight = serializers.SerializerMethodField()

    class Meta:
        model = Warehousedata
        fields= "__all__"

    def get_volume_weight(self, obj):
        try:
            # Ensure length, breadth, and height are converted to float and not None
            length = float(obj.length) if obj.length else 0
            breadth = float(obj.breadth) if obj.breadth else 0
            height = float(obj.height) if obj.height else 0
            return round((length * breadth * height) / 6000, 2)
        except Exception:
            return None
        



class ExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseModel
        fields = "__all__"

    def validate(self, data):
        """Ensure EMI payments are linked to a loan."""
        purpose = data.get("purpose_of_payment")
        loan = data.get("loan")

        if purpose and hasattr(purpose, 'name') and purpose.name.lower() == 'emi' and not loan:
            raise serializers.ValidationError({"loan": "EMI payments must be associated with a loan."})

        return data
class ExpenseExpectEmiSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = ExpenseModel
        fields = ['id','company','payed_by','bank',
                  'name','quantity','purpose_of_payment',
                  'amount','expense_date','transaction_id',
                  'description','added_by','expense_type']

class ExpenseGetSerializer(serializers.ModelSerializer):
    emi_name = serializers.CharField(source="loan.emi_name", read_only=True)
    purpose_of_payment_name = serializers.CharField(source="purpose_of_payment.name", read_only=True)
    class Meta:
        model = ExpenseModel
        fields = "__all__" 

class ExpenseSerializerAssest(serializers.ModelSerializer):
    
    class Meta:
        model = ExpenseModel
        fields = ['id','company','category','payed_by','bank',
                  'name','quantity','purpose_of_payment','amount',
                  'expense_date','transaction_id','description',
                  'added_by','asset_types','expense_type']

    

class ExpenseModelsSerializers(serializers.ModelSerializer):
    company = CompanyDetailsSerializer(read_only=True)
    payed_by = UserUpdateSerilizers(read_only=True)
    bank = Bankserializers(read_only=True)
    categoryname = serializers.SerializerMethodField()
    purpose_of_pay = serializers.SerializerMethodField()
    loanname = serializers.SerializerMethodField()

    class Meta:
        model = ExpenseModel
        fields = ['id', 'company', 'categoryname', 'payed_by', 'bank',
                  'purpose_of_payment', 'purpose_of_pay', 'amount',
                  'expense_date', 'transaction_id', 'description','expense_type',
                  'added_by', 'loan', 'name', 'quantity', 'asset_types', 'loanname']

    def get_categoryname(self, obj):
        return obj.category.category_name if obj.category else None

    def get_loanname(self, obj):
        return obj.loan.emi_name if obj.loan else None

    def get_purpose_of_pay(self, obj):
        return obj.purpose_of_payment.name if obj.purpose_of_payment else None

        
        
class ParcalSerializers(serializers.ModelSerializer):
    class Meta:
        model = ParcalService
        fields = "__all__"
        
        
        
class ProductSalesReportSerializer(serializers.ModelSerializer):
    order = serializers.CharField(source="order.invoice")
    product = serializers.CharField(source="product.name")
    total_sold = serializers.SerializerMethodField()
    total_amount = serializers.SerializerMethodField()
    manage_staff = serializers.CharField(source="order.manage_staff.name")
    family = serializers.CharField(source="order.family.name")

    class Meta:
        model = OrderItem
        fields = ["order", "product", "total_sold", "total_amount", "manage_staff","family"]

    def get_total_sold(self, obj):
        return obj.quantity  # Assuming `quantity` is the sold quantity

    

    def get_total_amount(self, obj):
        return obj.quantity * obj.rate  # Assuming `rate` is the price per unit



class ProductStockviewSerializres(serializers.ModelSerializer):
    stock = serializers.SerializerMethodField()

    class Meta:
        model = Products
        fields = ["id", "name", "stock", "selling_price","image"]


    def get_stock(self, obj):
        """
        Calculate the total stock for all products with the same groupID,
        including the current product.
        """
        products_in_group = Products.objects.filter(groupID=obj.groupID)
        total_stock = sum(product.stock for product in products_in_group)
        return total_stock

class WarehouseDetailSerializer(serializers.ModelSerializer):
    country = serializers.CharField(source='country_code.country_code', read_only=True)
    class Meta:
        model = WareHouse
        fields = ['id','name','address','location',
                  'country_code','country','unique_id']  
        
class RackDetailsModelSerializer(serializers.ModelSerializer):
    warehouse_name = serializers.CharField(source='warehouse.name', read_only=True)
    column_names = serializers.JSONField(read_only=True)  # Ensures it's not accepted on input

    class Meta:
        model = RackDetailsModel
        fields = ['id', 'warehouse', 
                  'warehouse_name', 'rack_name', 
                  'number_of_columns', 'column_names']
        
        
class ProductCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategoryModel
        fields = '__all__'

class OrderRequestSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    requested_by_name = serializers.CharField(source='requested_by.name', read_only=True)
    source_warehouse_name = serializers.CharField(source='source_warehouse.name', read_only=True)
    target_warehouse_name = serializers.CharField(source='target_warehouse.name', read_only=True)

    class Meta:
        model = OrderRequest
        fields = ['id', 'product', 'product_name', 'requested_by', 'requested_by_name', 'source_warehouse', 
                  'source_warehouse_name', 'target_warehouse', 'target_warehouse_name', 'quantity', 'status', 
                  'created_at', 'updated_at']
        

class AttendanceSerializer(serializers.ModelSerializer):
    staff_name = serializers.CharField(source='staff.name', read_only=True)
    staff_designation = serializers.CharField(source='staff.designation', read_only=True)

    class Meta:
        model = Attendance
        fields = ['id', 'staff', 'staff_name', 'staff_designation', 'date', 'attendance_status']        
        
    def validate_attendance_status(self, value):
        """
        Custom validation for attendance status to ensure it's one of the valid options.
        """
        if value not in ['Present', 'Absent', 'Half Day Leave']:
            raise serializers.ValidationError("Invalid status")
        return value

class UpdateCartPricesSerializer(serializers.ModelSerializer):
    selling_price = serializers.FloatField(required=False)
    retail_price = serializers.FloatField(required=False)

    class Meta:
        model = BeposoftCart
        fields = ['id', 'selling_price', 'retail_price']

    def update(self, instance, validated_data):
        # Update only if prices are provided
        if 'selling_price' in validated_data:
            instance.product.selling_price = validated_data['selling_price']
            instance.product.save()

        if 'retail_price' in validated_data:
            instance.product.retail_price = validated_data['retail_price']
            instance.product.save()

        return instance

class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choices
        fields = ['id', 'name'] 


    

class CompanyExpenseSeriizers(serializers.ModelSerializer):
    purpose_of_payment = ChoiceSerializer()  # Nested serializer

    class Meta :
        model = ExpenseModel
        fields = ['id','amount','expense_date','purpose_of_payment']



class BankbasedReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentReceipt
        fields = ['payment_receipt','amount','received_at']


class RefundReceiptSerializer(serializers.ModelSerializer):
    created_name = serializers.CharField(source='created_by.name', read_only=True)
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    invoice_no = serializers.CharField(source='invoice.invoice', read_only=True)
    bank_name = serializers.CharField(source='bank.name', read_only=True)
    class Meta:
        model = RefundReceipt
        fields = "__all__"
        

class UnifiedPaymentSerializer(serializers.Serializer):
    payment_receipt = serializers.CharField(allow_null=True)
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    received_at = serializers.DateField()

class FinanaceReceiptSerializer(serializers.ModelSerializer):
    payments = serializers.SerializerMethodField()
    banks = serializers.SerializerMethodField()  # changed to method field

    class Meta:
        model = Bank
        fields = ['id', 'name', 'open_balance', 'payments', 'banks']

    def get_payments(self, bank):
        from itertools import chain
        from django.db.models import F
        from django.db.models.functions import TruncDate

        payments_qs = bank.payments.all().values(
            'payment_receipt', 'amount', 'received_at'
        )

        advance_qs = bank.advance_receipts.all().values(
            'payment_receipt', 'amount', 'received_at'
        )

        bank_receipt_qs = bank.bank_receipts.all().values(
            'payment_receipt', 'amount', 'received_at'
        )

        # Internal transfers received
        internal_received = InternalTransfer.objects.filter(
            receiver_bank=bank
        ).annotate(
            received_at=TruncDate('created_at')
        ).values(
            'amount',
            'received_at',
            'payment_receipt'
        )

        # COD transfers received
        cod_received = CODTransfer.objects.filter(
            receiver_bank=bank
        ).annotate(
            received_at=TruncDate('created_end')
        ).values(
            'amount',
            'received_at',
            'payment_receipt'
        )

        combined = chain(
            payments_qs,
            advance_qs,
            bank_receipt_qs,
            internal_received,
            cod_received
        )

        return UnifiedPaymentSerializer(combined, many=True).data


    def get_banks(self, bank):
        from django.db.models import F
        from django.db.models.functions import TruncDate

        # Actual expenses
        expenses_qs = ExpenseModel.objects.filter(
            bank=bank
        ).values(
            'id', 'amount', 'expense_date', 'purpose_of_payment'
        )

        # Internal transfers sent
        internal_transfers_qs = InternalTransfer.objects.filter(
            sender_bank=bank
        ).annotate(
            expense_date=TruncDate('created_at')
        ).values(
            'amount',
            'expense_date',
            'transactionID'
        )

        internal_transfers = [
            {
                'id': None,
                'amount': t['amount'],
                'expense_date': t['expense_date'],
                'purpose_of_payment': t['transactionID'],
            }
            for t in internal_transfers_qs
        ]

        # COD transfers sent (NEW)
        cod_transfers_qs = CODTransfer.objects.filter(
            sender_bank=bank
        ).annotate(
            expense_date=TruncDate('created_at')
        ).values(
            'amount',
            'expense_date',
            'payment_receipt'
        )

        cod_transfers = [
            {
                'id': None,
                'amount': t['amount'],
                'expense_date': t['expense_date'],
                'purpose_of_payment': f"COD TRANSFER - {t['payment_receipt']}",
            }
            for t in cod_transfers_qs
        ]

        combined = list(expenses_qs) + internal_transfers + cod_transfers

        return CompanyExpenseSeriizers(combined, many=True).data



    
class InternalTransferSerializer(serializers.ModelSerializer):
    class Meta:
        model = InternalTransfer
        fields = '__all__'
        
class InternalTransferViewSerializer(serializers.ModelSerializer):
    sender_bank_name = serializers.CharField(source='sender_bank.name', read_only=True)
    receiver_bank_name = serializers.CharField(source='receiver_bank.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    
    class Meta:
        model = InternalTransfer
        fields = ['sender_bank','sender_bank_name','receiver_bank','id',
                  'receiver_bank_name','amount','description','created_at',
                  'transactionID','created_by','created_by_name']
        

class CODTransferSerializer(serializers.ModelSerializer):
    class Meta:
        model = CODTransfer
        fields = '__all__'
        
class CODTransferViewSerializer(serializers.ModelSerializer):
    sender_bank_name = serializers.CharField(source='sender_bank.name', read_only=True)
    receiver_bank_name = serializers.CharField(source='receiver_bank.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    
    class Meta:
        model = CODTransfer
        fields = ['sender_bank','sender_bank_name','receiver_bank','id', 'payment_receipt',
                  'receiver_bank_name','amount','description','created_at',
                  'created_end','transactionID','created_by','created_by_name']

class AttendanceSummarySerializer(serializers.Serializer):
    staff_id = serializers.IntegerField()
    staff_name = serializers.CharField()
    present_count = serializers.IntegerField()
    half_day_leave_count = serializers.IntegerField()
    absent_count = serializers.IntegerField()  


class AttendanceDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = ["date", "attendance_status"]

class AttendanceAbsenceSerializer(serializers.Serializer):
    staff_id = serializers.IntegerField(source='id')
    staff_name = serializers.CharField(source='name')
    absences = serializers.SerializerMethodField()

    def get_absences(self, obj):
        today = date.today()
        # Filter absences and half-day leaves up to today
        attendance_records = Attendance.objects.filter(
            staff=obj, 
            date__lte=today, 
            attendance_status__in=["Absent", "Half Day Leave"]
        ).order_by("date")

        # Serialize the filtered attendance records
        return AttendanceDetailSerializer(attendance_records, many=True).data    


class DataLogCreateSerializer(serializers.ModelSerializer):
    """
    Frontend supplies fields below; server injects user + created_at.
    """
    class Meta:
        model = DataLog
        # user & created_at are server-managed
        exclude = ['id', 'user', 'created_at']

class DataLogViewSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)
    order_name = serializers.CharField(source='order.invoice', read_only=True)

    class Meta:
        model = DataLog
        fields = '__all__'      

class ProductDateWiseReportSerializer(serializers.ModelSerializer):
    order_date = serializers.CharField(source='order.order_date', read_only=True)
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_stock = serializers.CharField(source='product.stock', read_only=True)
    order_status = serializers.CharField(source='order.status', read_only=True)
    total_amount = serializers.SerializerMethodField()

    class Meta:
        model = OrderItem
        fields = ['id', 'quantity','rate','discount',
                  'order_date','product','order', 'order_status',
                  'product_name','product_stock','total_amount']
    
    def get_total_amount(self, obj):
        """(rate - discount) * quantity"""
        rate = obj.rate or 0
        discount = obj.discount or 0
        qty = obj.quantity or 0
        return round((rate - discount) * qty, 2)
    

class ContactInfoSerializer(serializers.ModelSerializer):
    state_name = serializers.CharField(source='state.name', read_only=True)
    state_id = serializers.CharField(source='state.id', read_only=True)
    country_name = serializers.CharField(source='state.country.name', read_only=True)
    country_code = serializers.CharField(source='state.country.code', read_only=True)
    country_id = serializers.CharField(source='state.country.id', read_only=True)
    created = serializers.CharField(source='created_by.name', read_only=True)
    district = serializers.CharField(source='district.name', read_only=True)
    class Meta:
        model = ContactInfo
        fields = "__all__"
        read_only_fields = ['created_by']

class CallReportSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source = 'created_by.name', read_only=True)
    created_by_designation = serializers.CharField(source = 'created_by.designation', read_only=True)
    created_by_department_id = serializers.CharField(source = 'created_by.department_id.id', read_only=True)
    created_by_department_name = serializers.CharField(source = 'created_by.department_id.name', read_only=True)
    state_id = serializers.CharField(source = 'Customer.state.id', read_only=True)
    state = serializers.CharField(source = 'Customer.state.name', read_only=True)
    class Meta:
        model = CallReport
        fields = "__all__"
        read_only_fields = ["created_by", "created_at"]

class CallReportSortingSerializer(serializers.ModelSerializer):
    customer_first_name = serializers.CharField(source='Customer.first_name', read_only=True)
    customer_last_name = serializers.CharField(source='Customer.last_name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    state = serializers.CharField(source='Customer.state', read_only=True)
    state_name = serializers.CharField(source='Customer.state.name', read_only=True)
    country = serializers.CharField(source='Customer.state.country', read_only=True)
    country_name = serializers.CharField(source='Customer.state.country.name', read_only=True)
    class Meta:
        model = CallReport
        fields = '__all__'


class QuestionnaireSerializer(serializers.ModelSerializer):
    family_name = serializers.CharField(source='family.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.name', read_only=True)
    class Meta:
        model = Questionnaire
        fields = "__all__"
        read_only_fields = ('created_by',)


class AnswersSerializer(serializers.ModelSerializer):
    question_name = serializers.CharField(source='question.questions', read_only=True)
    family_name = serializers.CharField(source='family.name', read_only=True)
    added_by_name = serializers.CharField(source='added_by.name', read_only=True)
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    class Meta:
        model = Answers
        fields = "__all__"
        read_only_fields = ('added_by',)


class StaffOrderUpdateItemSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.category_name', read_only=True)
    class Meta:
        model = StaffOrderUpdateItem
        fields = ['category', 'quantity', 'invoice', 'volume', 'note1', 'description1', 'category_name']


class StaffOrderUpdateSerializer(serializers.ModelSerializer):
    staff_name = serializers.CharField(source='staff.name', read_only=True)
    customer_name = serializers.CharField(source='customer.name', read_only=True)
    customer_state = serializers.CharField(source='customer.state.name', read_only=True)
    items = StaffOrderUpdateItemSerializer(many=True)

    class Meta:
        model = StaffOrderUpdate
        fields = ['id', 'staff', 'customer', 'note', 'description', 'date',
                  'items', 'staff_name', 'customer_name', 'customer_state']
        extra_kwargs = {
            'staff': {'required': False},
        }

    def create(self, validated_data):
        items_data = validated_data.pop('items')
        parent = StaffOrderUpdate.objects.create(**validated_data)

        for item in items_data:
            StaffOrderUpdateItem.objects.create(parent=parent, **item)

        return parent

    def update(self, instance, validated_data):

        if "items" not in validated_data:
            raise serializers.ValidationError({"items": "This field is required."})

        StaffOrderUpdateItem.objects.filter(parent=instance).delete()

        items_data = validated_data.pop('items')

        instance.customer = validated_data.get('customer', instance.customer)
        instance.note = validated_data.get('note', instance.note)
        instance.description = validated_data.get('description', instance.description)
        instance.save()

        for item in items_data:
            StaffOrderUpdateItem.objects.create(parent=instance, **item)

        return instance


class OrderCODSplitUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ["box_count"]

    def validate_box_count(self, value):
        if value <= 0:
            raise serializers.ValidationError("Box count must be greater than zero.")
        return value


class AdvanceAmountTransferImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdvanceAmountTransferImage
        fields = ["id", "image", "uploaded_at"]


class AdvanceAmountTransferSerializer(serializers.ModelSerializer):
    amount_transfer_images = AdvanceAmountTransferImageSerializer(many=True, read_only=True)
    send_from_name = serializers.CharField(source="send_from.name", read_only=True)
    send_to_name = serializers.CharField(source="send_to.name", read_only=True)
    created_by_name = serializers.CharField(source="created_by.name", read_only=True)

    class Meta:
        model = AdvanceAmountTransfer
        fields = [
            "id", "send_from", "send_from_name",
            "send_to", "send_to_name", "amount",
            "note", "date", "created_by",
            "created_by_name", "created_at",
            "updated_at", "amount_transfer_images",
        ]
        read_only_fields = ["created_by", "created_at", "updated_at"]



# Seller related serializers

class ProductSellerDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductSellerDetails
        fields = "__all__"
        read_only_fields = ["created_by", "created_at", "updated_at"]



class ProductSellerInvoiceItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source="product.name", read_only=True)

    class Meta:
        model = ProductSellerInvoiceItem
        fields = "__all__"


class ProductSellerInvoiceSerializer(serializers.ModelSerializer):
    items = ProductSellerInvoiceItemSerializer(many=True, read_only=True)
    seller_name = serializers.CharField(source="seller.name", read_only=True)

    class Meta:
        model = ProductSellerInvoice
        fields = "__all__"
