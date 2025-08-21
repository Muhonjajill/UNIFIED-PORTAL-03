from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from .views import SettingsView, manage_file_categories


urlpatterns = [
    #path('', auth_views.LoginView.as_view(template_name='accounts/login.html'), name='login'),
    path('', views.login_view, name='login'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),

    path('register/', views.register_view, name='register'),

        
    path('password-reset/', auth_views.PasswordResetView.as_view(
        template_name='accounts/password_reset_form.html'), name='password_reset'),

    
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='accounts/password_reset_done.html'), name='password_reset_done'),

   
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='accounts/password_reset_confirm.html'), name='password_reset_confirm'),

    
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='accounts/password_reset_complete.html'), name='password_reset_complete'),


    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('create-user/', views.create_user, name='create_user'),

    path('pre_dashboards/', views.pre_dashboards, name='pre_dashboards'),
    

    path('users/', views.user_list_view, name='user_list'),
    path('users/<int:user_id>/', views.user_detail, name='user_detail'),  
    path('users/<int:user_id>/edit/', views.edit_user, name='edit_user'),  
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'), 


    path('files-management/', views.file_management_dashboard, name='file_management_dashboard'),
    path('dashboard/', views.file_management_dashboard, name='dashboard'),
    path('files-management/', views.file_management_dashboard, name='dashboard'),
    path('file-categories/', manage_file_categories, name='manage_file_categories'),

     path('search/', views.search, name='search'),

    path('profile/', views.profile_view, name='profile_view'),
    path('settings/', SettingsView.as_view(), name='settings'),

    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='accounts/password_change.html'), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='accounts/password_change_done.html'), name='password_change_done'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),

    path('files/', views.file_list_view, name='file_list'),
    path('files/category/<str:category_name>/', views.file_list_view, name="file_list_by_category"),
    path('files/upload/', views.upload_file_view, name='upload_file'),
    path('files/preview/<int:file_id>/', views.preview_file, name='preview_file'),
    path('files/delete/<int:file_id>/', views.delete_file, name='delete_file'),


    path('ticketing/', views.ticketing_dashboard, name='ticketing_dashboard'),
    path('tickets/', views.tickets, name='tickets'),
    path('create_ticket/', views.create_ticket, name= 'create_ticket'),
    path('tickets/<int:ticket_id>/', views.ticket_detail, name='ticket_detail'), 
    path('comments/<int:comment_id>/edit/', views.edit_comment, name='edit_comment'),
    path('comments/<int:comment_id>/delete/', views.delete_comment, name='delete_comment'),
    path('ticket/<int:ticket_id>/resolve/', views.resolve_ticket_view, name='resolve_ticket'),
    path('tickets/<int:ticket_id>/escalate/', views.escalate_ticket, name='escalate_ticket'),
    path('tickets/delete/<int:ticket_id>/', views.delete_ticket, name='delete_ticket'),
    path('ticket-statuses/', views.ticket_statuses, name='ticket_statuses'),
    path('tickets/status/<str:status>/', views.tickets_by_status, name='ticket_by_status'),
    path('problem-categories/', views.problem_category, name='problem_category'), 
    path('create_problem_category/', views.create_problem_category, name='create_problem_category'),
    path('categories/edit/<int:category_id>/', views.edit_problem_category, name='edit_problem_category'),
    path('categories/delete/<int:category_id>/', views.delete_problem_category, name='delete_problem_category'),

    # Master Data
    path('master-data/customers/', views.customers, name='customers'),
    path("customers/create/", views.create_customer, name="create_customer"),
    path('customers/delete/<int:id>/', views.delete_customer, name='delete_customer'),

    path('master-data/regions/', views.regions, name='regions'),
    path('regions/delete/<int:region_id>/', views.delete_region, name='delete_region'),
    path('regions/add/', views.regions, name='add_region'), 
    
    path('master-data/terminals/', views.terminals, name='terminals'),
    path('terminals/edit/<int:terminal_id>/', views.edit_terminal, name='edit_terminal'),
    path('terminals/delete/<int:terminal_id>/', views.delete_terminal, name='delete_terminal'),
    path('tickets/terminal/<int:terminal_id>/', views.fetch_tickets, name='fetch_tickets'),
    path('get_terminal_details/<int:terminal_id>/', views.get_terminal_details, name='get_terminal_details'),

    path('master-data/units/', views.units, name='units'),
    path('units/delete/<int:unit_id>/', views.delete_unit, name='delete_unit'),

    path('master-data/users/', views.system_users, name='system_users'), 
    path('users/delete/<int:user_id>/', views.delete_system_user, name='delete_user'),

    path('master-data/zones/', views.zones, name='zones'),
    path('zones/delete/<int:zone_id>/', views.delete_zone, name='delete_zone'),

    # Reports
    path('reports/general/', views.reports, name='reports'),
    path('statistics/', views.statistics_view, name='statistics'),
    path('export_report', views.export_report, name='export_report'),
    path('reports/version-controls/', views.version_controls, name='version_controls'),
    path('versions/<int:pk>/', views.version_detail, name='version_detail'),
    path('versions/<int:pk>/edit/', views.edit_version, name='edit_version'),
    path('versions/<int:pk>/delete/', views.delete_version, name='delete_version'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
