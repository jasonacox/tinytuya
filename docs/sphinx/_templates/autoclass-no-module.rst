{{ fullname | escape | underline}}

.. currentmodule:: {{ module }}

.. autoclass:: {{ objname }}
   :show-inheritance:
   :undoc-members:

   {% block methods %}
   {% if methods %}
   .. rubric:: {{ _('Methods provided by this class') }}

   .. autosummary::
   {% for item in methods %}
   {%- if item not in inherited_members %}
      ~{{ name }}.{{ item }}
   {%- endif %}
   {%- endfor %}

   .. rubric:: {{ _('Methods inherited from parent class') }}

   .. autosummary::
   {% for item in methods %}
   {%- if item in inherited_members %}
      ~{{ name }}.{{ item }}
   {%- endif %}
   {%- endfor %}

   {% for item in methods %}

   .. automethod:: {{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block attributes %}
   {% if attributes %}
   .. rubric:: {{ _('Attributes') }}

   .. autosummary::
   {% for item in attributes %}
      ~{{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}
