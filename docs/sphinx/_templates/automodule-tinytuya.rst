{{ fullname + _(' module') | escape }}
===================================

.. automodule:: {{ fullname }}
   :show-inheritance:
   :members:
   :undoc-members:
   :imported-members:

   .. currentmodule:: tinytuya

   {% block attributes %}
   {%- if attributes %}
   .. rubric:: {{ _('Module Attributes') }}

   .. autosummary::
   {% for item in attributes %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {%- endblock %}

   {%- block functions %}
   {%- if functions %}
   .. rubric:: {{ _('Functions') }}

   .. autosummary::
   {% for item in functions %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {%- endblock %}

   {%- block classes %}
   {%- if classes %}
   .. rubric:: {{ _('Classes') }}

   .. autosummary::
   {% for item in classes %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {%- endblock %}

   {%- block exceptions %}
   {%- if exceptions %}
   .. rubric:: {{ _('Exceptions') }}

   .. autosummary::
   {% for item in exceptions %}
      {{ item }}
   {%- endfor %}
   {% endif %}
   {%- endblock %}

   {%- block other %}
   .. rubric:: {{ _('Extras') }}

   .. autosummary::
      :toctree:
      :template: automodule-tinytuya-core.rst
      {% for item in tinytuya_core_autodocument %}
      ~core.{{ item }}
      {%- endfor %}
   {% endblock %}

{%- block modules %}
{%- if modules %}
.. rubric:: Modules

.. autosummary::
   :toctree:
{% for item in modules %}
   {{ item }}
{%- endfor %}
{% endif %}
{%- endblock %}
