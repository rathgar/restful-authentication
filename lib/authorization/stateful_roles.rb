module Authorization
  module StatefulRoles
    unless Object.constants.include? "STATEFUL_ROLES_CONSTANTS_DEFINED"
      STATEFUL_ROLES_CONSTANTS_DEFINED = true # sorry for the C idiom
    end
    
    def self.included( recipient )
      recipient.extend( StatefulRolesClassMethods )
      recipient.class_eval do
        include StatefulRolesInstanceMethods
        

        state_machine :initial => :passive do
          state :passive
          state :pending
          state :active
          state :suspended
          state :deleted

          before_transition any => :pending, do: :make_activation_code
          before_transition any => :active, do: :do_activate
          before_transition any => :deleted, do: :do_delete

          event :register do
            transition :passive => :pending, :unless => Proc.new {|u| (u.crypted_password.blank? && u.password.blank?) }
          end

          event :activate do
            transition :pending => :active
          end

          event :suspend do
            transition [:passive, :pending, :active] => :suspended
          end

          event :delete do
            transition [:passive, :pending, :active, :suspended] => :deleted
          end

          event :unsuspend do
            transition :suspended => :active,  :unless => Proc.new {|u| u.activated_at.blank? }
            transition :suspended => :pending, :unless => Proc.new {|u| u.activation_code.blank? }
            transition :suspended => :passive
          end
        end
      end
    end

    module StatefulRolesClassMethods
    end # class methods

    module StatefulRolesInstanceMethods
      # Returns true if the user has just been activated.
      def recently_activated?
        @activated
      end
      def do_delete
        self.deleted_at = Time.now.utc
      end

      def do_activate
        @activated = true
        self.activated_at = Time.now.utc
        self.deleted_at = self.activation_code = nil
      end
    end # instance methods
  end
end
