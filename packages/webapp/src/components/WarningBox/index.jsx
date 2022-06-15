import React from 'react';
import styles from './styles.module.scss';
import clsx from 'clsx';
import { VscWarning } from 'react-icons/all';

export default function PureWarningBox({ children, className, iconClassName, ...props }) {
  return (
    <div className={clsx(styles.warningBox, className)} {...props}>
      <VscWarning className={clsx(styles.icon, iconClassName)} />
      {children}
    </div>
  );
}
